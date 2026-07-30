pub struct NatsPublisherForTesting {
    client: async_nats::Client,
}

impl NatsPublisherForTesting {
    pub async fn new(port: u16) -> Self {
        let addr = format!("127.0.0.1:{}", port);
        log::debug!("The testing NATS publisher is connecting to {}..", addr);
        Self {
            client: async_nats::connect(addr)
                .await
                .expect("should be able to connect to NATS server"),
        }
    }

    pub async fn publish(&self, subject: String, payload: Vec<u8>) {
        log::trace!("publishing {} ({} bytes)", subject, payload.len());
        self.client
            .publish(subject, payload.into())
            .await
            .expect("should be able to publish");
    }

    /// Waits until the NATS server has processed everything published so far.
    ///
    /// A flush() only empties the client's write buffer, without waiting for
    /// the server. This publishes a probe message to an inbox subscribed on
    /// this same connection and waits for it to come back: the server handles
    /// the commands of a connection in order, so receiving the probe implies
    /// all earlier publishes were processed and routed to their subscribers.
    pub async fn sync(&self) {
        use futures::StreamExt;
        use std::time::Duration;

        let inbox = self.client.new_inbox();
        let mut probe_sub = self
            .client
            .subscribe(inbox.clone())
            .await
            .expect("should be able to subscribe to the probe inbox");
        self.client
            .publish(inbox, "".into())
            .await
            .expect("should be able to publish the probe");
        self.client
            .flush()
            .await
            .expect("should be able to flush the probe");
        tokio::time::timeout(Duration::from_secs(5), probe_sub.next())
            .await
            .expect("should receive the probe back within 5 seconds")
            .expect("should receive the probe back");
    }
}
