use std::net::IpAddr;
use rocket::http::Status;
use rocket::request::{FromRequest, Request, Outcome};

pub struct ClientRealAddr(pub IpAddr);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ClientRealAddr {
    type Error = ();

    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        if let Some(forwarded) = req.headers().get_one("X-Forwarded-For") {
            if let Ok(ip) = forwarded.split(',').next().unwrap_or("").trim().parse() {
                return Outcome::Success(ClientRealAddr(ip));
            }
        }
        
        match req.client_ip() {
            Some(ip) => Outcome::Success(ClientRealAddr(ip)),
            None => Outcome::Forward(Status::BadRequest),
        }
    }
}
