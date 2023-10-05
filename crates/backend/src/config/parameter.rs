use dotenv;

pub fn init() {
   dotenv::dotenv().expect("failed to load .env file");
}

pub fn get_param(param: &str) -> String {
   std::env::var(param).unwrap_or_else(|_| panic!("{} is not defined in the environment", param))
}
