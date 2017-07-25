//! Retrieves configuration of the network interfaces of the local system.

#![feature(ip, try_from)]

extern crate c_linked_list;
extern crate libc;

use std::{io, mem};
use std::convert::{TryFrom, TryInto};
use std::ffi::CStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use c_linked_list::CLinkedList;

/// Details about a network interface on the local system.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct Interface {
    /// The name of this interface.
    pub name: String,
    /// The address of this interface.
    pub addr: IpAddr,
    /// The netmask of this interface.
    pub netmask: IpAddr,
    /// The broadcast address of this interface.
    pub broadcast: Option<IpAddr>,
    /// The point-to-point destination address of this interface.
    pub destination: Option<IpAddr>,
}

impl Interface {
    /// Returns [`true`] if this interface has an [IPv4 address], and [`false`] otherwise.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [`false`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv4 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V4
    pub fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Returns [`true`] if this interface has an [IPv6 address], and [`false`] otherwise.
    ///
    /// [`true`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [`false`]: https://doc.rust-lang.org/std/primitive.bool.html
    /// [IPv6 address]: https://doc.rust-lang.org/std/net/enum.IpAddr.html#variant.V6
    pub fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    /// Returns [`true`] if this interface has a loopback address.
    ///
    /// [`true`]: ../../std/primitive.bool.html
    pub fn is_loopback(&self) -> bool {
        self.addr.is_loopback()
    }
}

impl<'a> TryFrom<&'a libc::ifaddrs> for Interface {
    type Error = io::Error;

    fn try_from(ifaddr: &'a libc::ifaddrs) -> Result<Self, Self::Error> {
        if ifaddr.ifa_addr.is_null() {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }

        let name = unsafe { CStr::from_ptr(ifaddr.ifa_name as *const _) }
            .to_string_lossy()
            .into_owned();

        CSockAddrPtr(ifaddr.ifa_addr).try_into().and_then(|addr| {
            let netmask = match addr {
                IpAddr::V4(_) => {
                    match CSockAddrPtr(ifaddr.ifa_netmask).try_into() {
                        Ok(IpAddr::V4(v)) => IpAddr::V4(v),
                        _ => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    }
                }
                IpAddr::V6(_) => {
                    match CSockAddrPtr(ifaddr.ifa_netmask).try_into() {
                        Ok(IpAddr::V6(v)) => IpAddr::V6(v),
                        _ => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)),
                    }
                }
            };

            let broadcast = match (ifaddr.ifa_flags & 2) != 0 {
                true => {
                    match addr {
                        IpAddr::V4(_) => {
                            match CSockAddrPtr(broad_dest_addr(ifaddr)).try_into() {
                                Ok(IpAddr::V4(v)) => Some(IpAddr::V4(v)),
                                _ => None,
                            }
                        }
                        IpAddr::V6(_) => {
                            match CSockAddrPtr(broad_dest_addr(ifaddr)).try_into() {
                                Ok(IpAddr::V6(v)) => Some(IpAddr::V6(v)),
                                _ => None,
                            }
                        }
                    }
                }
                false => None,
            };

            let destination = match (ifaddr.ifa_flags & 16) != 0 {
                true => {
                    match addr {
                        IpAddr::V4(_) => {
                            match CSockAddrPtr(broad_dest_addr(ifaddr)).try_into() {
                                Ok(IpAddr::V4(v)) => Some(IpAddr::V4(v)),
                                _ => None,
                            }
                        }
                        IpAddr::V6(_) => {
                            match CSockAddrPtr(broad_dest_addr(ifaddr)).try_into() {
                                Ok(IpAddr::V6(v)) => Some(IpAddr::V6(v)),
                                _ => None,
                            }
                        }
                    }
                }
                false => None,
            };

            Ok(Interface {
                name,
                addr,
                netmask,
                broadcast,
                destination,
            })
        })
    }
}

#[cfg(target_os = "linux")]
fn broad_dest_addr(ifaddr: &libc::ifaddrs) -> *const libc::sockaddr {
    ifaddr.ifa_ifu
}

#[cfg(target_os = "macos")]
fn broad_dest_addr(ifaddr: &libc::ifaddrs) -> *const libc::sockaddr {
    ifaddr.ifa_dstaddr
}

struct CSockAddrPtr(*const libc::sockaddr);

impl TryInto<IpAddr> for CSockAddrPtr {
    type Error = io::Error;

    fn try_into(self) -> Result<IpAddr, Self::Error> {
        if self.0.is_null() {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }

        match unsafe { *self.0 }.sa_family as u32 {
            v if v == libc::AF_INET as u32 => {
                let sa = &unsafe { *(self.0 as *const libc::sockaddr_in) };
                let addr = Ipv4Addr::new(
                    ((sa.sin_addr.s_addr) & 255) as u8,
                    ((sa.sin_addr.s_addr >> 8) & 255) as u8,
                    ((sa.sin_addr.s_addr >> 16) & 255) as u8,
                    ((sa.sin_addr.s_addr >> 24) & 255) as u8,
                );
                if addr.is_link_local() {
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                } else {
                    Ok(IpAddr::V4(addr))
                }
            }
            v if v == libc::AF_INET6 as u32 => {
                let sa = &unsafe { *(self.0 as *const libc::sockaddr_in6) };
                let addr =
                    Ipv6Addr::new(
                        ((sa.sin6_addr.s6_addr[0] as u16) << 8 | sa.sin6_addr.s6_addr[1] as u16),
                        ((sa.sin6_addr.s6_addr[2] as u16) << 8 | sa.sin6_addr.s6_addr[3] as u16),
                        ((sa.sin6_addr.s6_addr[4] as u16) << 8 | sa.sin6_addr.s6_addr[5] as u16),
                        ((sa.sin6_addr.s6_addr[6] as u16) << 8 | sa.sin6_addr.s6_addr[7] as u16),
                        ((sa.sin6_addr.s6_addr[8] as u16) << 8 | sa.sin6_addr.s6_addr[9] as u16),
                        ((sa.sin6_addr.s6_addr[10] as u16) << 8 | sa.sin6_addr.s6_addr[11] as u16),
                        ((sa.sin6_addr.s6_addr[12] as u16) << 8 | sa.sin6_addr.s6_addr[13] as u16),
                        ((sa.sin6_addr.s6_addr[14] as u16) << 8 | sa.sin6_addr.s6_addr[15] as u16),
                    );
                if addr.is_unicast_link_local() {
                    Err(io::Error::from(io::ErrorKind::AddrNotAvailable))
                } else {
                    Ok(IpAddr::V6(addr))
                }
            }
            _ => Err(io::Error::from(io::ErrorKind::InvalidData)),
        }
    }
}

/// Creates a vector of structures describing the network interfaces of the local system.
pub fn get_if_addrs() -> Result<Vec<Interface>, io::Error> {
    let mut ifaddrs: *mut libc::ifaddrs;
    unsafe {
        ifaddrs = mem::uninitialized();
        if 0 != libc::getifaddrs(&mut ifaddrs) {
            return Err(io::Error::last_os_error());
        }
    }

    let addrs = unsafe { CLinkedList::from_mut_ptr(ifaddrs, |a| a.ifa_next) }
        .iter()
        .filter_map(|ifaddr| TryFrom::try_from(ifaddr).ok())
        .collect::<Vec<_>>();

    unsafe {
        libc::freeifaddrs(ifaddrs);
    }

    Ok(addrs)
}

#[cfg(test)]
mod tests {
    #[test]
    fn c_sock_addr_ptr_to_ipv4addr() {
        use super::CSockAddrPtr;
        use std::{io, mem};
        use std::convert::TryInto;
        use std::net::IpAddr;
        use libc;

        let sain = libc::sockaddr_in {
            sin_family: libc::AF_INET as _,
            sin_addr: libc::in_addr { s_addr: 127 | 0 << 8 | 0 << 16 | 1 << 24 },
            ..unsafe { mem::zeroed() }
        };
        let sainptr: *const libc::sockaddr_in = &sain;
        let sa = &unsafe { *(sainptr as *const libc::sockaddr) };
        let addr: Result<IpAddr, io::Error> = CSockAddrPtr(sa).try_into();
        assert_eq!(addr.unwrap(), IpAddr::V4("127.0.0.1".parse().ok().unwrap()));
    }
}
