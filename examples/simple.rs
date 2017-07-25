extern crate get_if_addrs;

use get_if_addrs::get_if_addrs;

fn main() {
    if let Ok(addrs) = get_if_addrs() {
        for addr in addrs {
            println!("{:?}", addr);
        }
    }
}
