pub type Result<T> = std::result::Result<T, CloudError>;

#[derive(Debug)]
pub enum CloudError {
    GrpcStatus(tonic::Status),
    GrpcTransport(tonic::transport::Error),
    InvaildBlock,
    SendMsgFailed,
}

impl std::fmt::Display for CloudError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for CloudError {}

impl From<tonic::Status> for CloudError {
    fn from(error: tonic::Status) -> Self {
        Self::GrpcStatus(error)
    }
}

impl From<tonic::transport::Error> for CloudError {
    fn from(error: tonic::transport::Error) -> Self {
        Self::GrpcTransport(error)
    }
}

impl From<CloudError> for Box<dyn std::error::Error + Send> {
    fn from(error: CloudError) -> Self {
        Box::new(error) as Box<dyn std::error::Error + Send>
    }
}
