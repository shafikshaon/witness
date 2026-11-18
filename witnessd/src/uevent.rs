//! USB and block-device attach/detach from the kernel's uevent netlink group (DESIGN.md §2.4).
//!
//! Group 1 carries the kernel's own events, so no libudev is needed. The vendor, product and
//! serial strings are not in the uevent; they are read from sysfs when the device appears.

use std::collections::HashMap;
use std::path::Path;

use witness_common::schema::{BlockDevice, Body, DeviceAction, UsbDevice};

/// A parsed uevent: `ACTION@devpath\0KEY=VALUE\0...`.
#[derive(Debug, PartialEq, Eq)]
pub struct Uevent {
    pub action: String,
    pub vars: HashMap<String, String>,
}

pub fn parse(buf: &[u8]) -> Option<Uevent> {
    // udev-originated messages start with "libudev" and carry a binary header; we listen to
    // the kernel group only, but ignore anything that is not the kernel format.
    let mut parts = buf.split(|&b| b == 0);
    let head = std::str::from_utf8(parts.next()?).ok()?;
    let (action, _devpath) = head.split_once('@')?;
    let vars = parts
        .filter_map(|p| std::str::from_utf8(p).ok()?.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Some(Uevent {
        action: action.into(),
        vars,
    })
}

fn sysfs_str(sys: &Path, devpath: &str, file: &str) -> Option<String> {
    let p = sys.join(devpath.trim_start_matches('/')).join(file);
    let s = std::fs::read_to_string(p).ok()?;
    let s = s.trim();
    (!s.is_empty()).then(|| s.to_string())
}

/// Turns a uevent into a schema body, or `None` for events we do not report (anything other
/// than add/remove of a USB device or a whole block device).
pub fn to_body(ev: &Uevent, sys: &Path) -> Option<Body> {
    let action = match ev.action.as_str() {
        "add" => DeviceAction::Add,
        "remove" => DeviceAction::Remove,
        _ => return None,
    };
    let get = |k: &str| ev.vars.get(k).map(String::as_str);
    let devpath = get("DEVPATH")?.to_string();
    match (get("SUBSYSTEM")?, get("DEVTYPE")) {
        ("usb", Some("usb_device")) => {
            // PRODUCT=<vendor hex>/<product hex>/<bcd>, TYPE=<class>/<sub>/<proto>.
            let mut p = get("PRODUCT")?.split('/');
            let (vendor_id, product_id) = (p.next()?.to_string(), p.next()?.to_string());
            Some(Body::UsbDevice(UsbDevice {
                action,
                vendor: sysfs_str(sys, &devpath, "manufacturer"),
                product: sysfs_str(sys, &devpath, "product"),
                serial: sysfs_str(sys, &devpath, "serial"),
                class: get("TYPE")
                    .and_then(|t| t.split('/').next())
                    .map(String::from),
                devpath,
                vendor_id,
                product_id,
            }))
        }
        ("block", Some("disk")) => {
            let sectors = sysfs_str(sys, &devpath, "size").and_then(|s| s.parse::<u64>().ok());
            Some(Body::BlockDevice(BlockDevice {
                action,
                name: get("DEVNAME")?.rsplit('/').next()?.to_string(),
                size_bytes: sectors.map(|n| n.saturating_mul(512)),
                model: sysfs_str(sys, &devpath, "device/model"),
                serial: sysfs_str(sys, &devpath, "device/serial"),
                removable: sysfs_str(sys, &devpath, "removable").as_deref() == Some("1"),
                devpath,
            }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(parts: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for p in parts {
            v.extend(p.as_bytes());
            v.push(0);
        }
        v
    }

    #[test]
    fn usb_add_reads_strings_from_sysfs() {
        let d = tempfile::tempdir().unwrap();
        let dev = d.path().join("devices/pci0/usb1/1-2");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("manufacturer"), "ACME\n").unwrap();
        std::fs::write(dev.join("product"), "Stick\n").unwrap();
        std::fs::write(dev.join("serial"), "S123\n").unwrap();
        let ev = parse(&msg(&[
            "add@/devices/pci0/usb1/1-2",
            "ACTION=add",
            "DEVPATH=/devices/pci0/usb1/1-2",
            "SUBSYSTEM=usb",
            "DEVTYPE=usb_device",
            "PRODUCT=781/5581/100",
            "TYPE=0/0/0",
        ]))
        .unwrap();
        let Some(Body::UsbDevice(u)) = to_body(&ev, d.path()) else {
            panic!()
        };
        assert_eq!(
            (u.vendor_id.as_str(), u.product_id.as_str()),
            ("781", "5581")
        );
        assert_eq!(u.vendor.as_deref(), Some("ACME"));
        assert_eq!(u.serial.as_deref(), Some("S123"));
        assert_eq!(u.class.as_deref(), Some("0"));
        assert_eq!(u.action, DeviceAction::Add);
    }

    #[test]
    fn only_whole_block_disks_and_usb_devices_are_reported() {
        let d = tempfile::tempdir().unwrap();
        let mk = |sub: &str, ty: &str, act: &str| {
            parse(&msg(&[
                &format!("{act}@/devices/x"),
                "DEVPATH=/devices/x",
                &format!("SUBSYSTEM={sub}"),
                &format!("DEVTYPE={ty}"),
                "DEVNAME=sdb",
                "PRODUCT=1/2/3",
            ]))
            .unwrap()
        };
        assert!(matches!(
            to_body(&mk("block", "disk", "remove"), d.path()),
            Some(Body::BlockDevice(b)) if b.name == "sdb" && b.action == DeviceAction::Remove
        ));
        assert!(to_body(&mk("block", "partition", "add"), d.path()).is_none());
        assert!(to_body(&mk("usb", "usb_interface", "add"), d.path()).is_none());
        assert!(to_body(&mk("block", "disk", "change"), d.path()).is_none());
    }

    #[test]
    fn garbage_is_ignored() {
        assert!(parse(b"").is_none());
        assert!(parse(b"libudev\0\xfe\xed\xca\xfe").is_none());
    }
}
