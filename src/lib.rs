

extern crate uuid;

#[macro_use]
extern crate validator_derive;
extern crate validator;

use validator::{Validate};

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use uuid::Uuid;

pub struct AccountId {
    id: Uuid
}

pub struct Account {
    pub id : AccountId
}

pub struct UserId {
    pub id : Uuid
}

#[derive(Clone)]
pub struct Username {
    pub value : String
}

#[derive(Debug, Validate, Deserialize, Clone)]
pub struct Email {
    #[validate(email)]
    pub value : String
}

pub struct HashedPassword {
    pub value : String
}

#[derive(Debug, Validate, Deserialize)]
pub struct UnhashedPassword {
    #[validate(length(min = 8, max = 32))]
    pub value : String
}

pub struct User {
    pub id        : UserId,
    pub username  : Username,
    pub password  : HashedPassword,
    pub accountId : AccountId
}

pub struct RegisterWithEmailAndConfirmPasswordDto {
    id       : Uuid,
    username : Email, 
    password : UnhashedPassword
}

pub struct PasswordHashError {
    msg : String
}

pub struct OkRes<T> {
    item : T,
    log_msg : String
}

pub struct FindUserByEmailError {
    log_msg : String
}

pub struct LogMsg {
    pub msg : String
}

pub enum RepoReadOk {
    FindUserByEmailOk(User,LogMsg)
}

pub enum RepoReadErr {
    FindUserByEmailError(LogMsg)
}

pub enum RepoWriteOk {
    InserUserOk(User,LogMsg)
}

pub enum RepoWriteErr {
    InserUserErr(LogMsg)
}

pub struct EmailSentEr {
    pub logMsg : LogMsg
}


pub enum LogSeverity {
    Debug,
    Info,
    Warn,
    Error
}

pub struct Log {
    pub severity  : LogSeverity,
    pub msg       : String,
    pub timestamp : String
}

pub struct FindAllUsersOk {
    pub users : Vec<User>,
    pub log   : Log
}

pub struct FindUserByEmailErr {
    pub log : Log
}

pub struct InsertUserOk {
    logs : Vec<Log>
}

pub struct InsertUserErr {
    logs : Vec<Log>
}

pub struct EmailSentOk {}

pub struct EmailSentErr {
    logs : Vec<Log>
}

pub struct UserDeletedOk {}

pub struct UserDeletedErr {}

pub struct RegisterWithEmailAndConfirmPasswordReq {
    pub dto                : RegisterWithEmailAndConfirmPasswordDto,
    pub find_user_by_email : fn () -> Result<FindAllUsersOk,FindUserByEmailErr>,
    pub hash_password      : fn (&UnhashedPassword) -> Result<HashedPassword,PasswordHashError>,
    pub insert_user        : fn (&User) -> Result<InsertUserOk,InsertUserErr>,
    pub send_verification  : fn (&Email) -> Result<EmailSentOk,EmailSentErr>,
    pub delete_user        : fn (&UserId) -> Result<UserDeletedOk,UserDeletedErr>
}

pub struct RegisterSuperUserReq {

}

pub enum RegisterUserRequest {
    RegisterWithEmailAndConfirmPassword(RegisterWithEmailAndConfirmPasswordReq),
    RegisterSuperUser(RegisterSuperUserReq)
}

pub struct RegistrationOk {
    pub log_msg : LogMsg
}

pub enum RegistrationErr {
    InvalidEmailAndPassword,
    InvalidEmail,
    InvalidPassword,
    RepositoryError,
    UserExists,
    ProblemHashingPassword,
    ProblemInserting,
    CouldNotSendVerificationEmail
}

pub fn register_user_with_email_and_confirmation_password(req : RegisterWithEmailAndConfirmPasswordReq) -> Result<RegistrationOk,RegistrationErr> {

    match (req.dto.username.validate(), req.dto.password.validate()) {
        (Err(invalid_email),Err(invalid_pass)) => Err(RegistrationErr::InvalidEmailAndPassword),
        (Err(invalid_email),_)  => Err(RegistrationErr::InvalidEmail),
        (_,Err(invalid_pass))   => Err(RegistrationErr::InvalidPassword),
        (Ok(valid_email),Ok(_)) => {

            let users_res = (req.find_user_by_email)();

            let user_opt_res = match users_res {
                Err(_) => Err(""),
                Ok(users) => {

                    let user_opt = users.users.into_iter().find(|u| u.username.value == req.dto.username.value);

                    Ok(user_opt)
                }
            };

            match user_opt_res {
                Err(_) => Err(RegistrationErr::RepositoryError),
                Ok(Some(_)) => Err(RegistrationErr::UserExists),
                Ok(None) => {
                    
                    let hashed_password_res = (req.hash_password)(&req.dto.password);

                    match hashed_password_res {
                        Err(_) => Err(RegistrationErr::ProblemHashingPassword),
                        Ok(hashed_password) => {

                            let username = Username { value : req.dto.username.clone().value };

                            let user_id = UserId { id : Uuid::new_v4() };

                            let account_id = AccountId { id : Uuid::new_v4() };

                            let user = User {
                                id        : user_id, 
                                username  : username , 
                                password  : hashed_password , 
                                accountId : account_id 
                            };

                            let insert_res = (req.insert_user)(&user);

                            match insert_res {
                                Err(_) => Err(RegistrationErr::ProblemInserting),
                                Ok(_) => {

                                    match (req.send_verification)(&req.dto.username) {
                                        Err(_) => {
                                            (req.delete_user)(&user.id);
                                            Err(RegistrationErr::CouldNotSendVerificationEmail)
                                        },
                                        Ok(_) => {

                                            let log_msg = LogMsg { msg : "User Registered Ok".to_string() };

                                            Ok(RegistrationOk{ log_msg: log_msg })
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
