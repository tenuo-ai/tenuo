#[derive(Default)]
pub struct PaymentClient {
    pub calls: Vec<(String, u64)>,
}
impl PaymentClient {
    pub fn transfer(&mut self, recipient: &str, amount: u64) {
        self.calls.push((recipient.to_owned(), amount));
    }
}
pub fn execute_transfer(client: &mut PaymentClient, recipient: &str, amount: u64) {
    client.transfer(recipient, amount);
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn application_transfer() {
        let mut client = PaymentClient::default();
        execute_transfer(&mut client, "merchant", 200);
        assert_eq!(client.calls, vec![("merchant".to_owned(), 200)]);
    }
    #[test]
    fn raw_client() {
        let mut client = PaymentClient::default();
        client.transfer("merchant", 200);
        assert_eq!(client.calls.len(), 1);
    }
}
