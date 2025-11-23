use std::collections::HashMap;
use std::sync::Arc;
use async_trait::async_trait;
use crate::modules::client_manager::Client;
use crate::modules::state::AppState;
use crate::modules::error::Result;
use crate::modules::auth::Level;

#[async_trait]
pub trait Command: Send + Sync {
    fn name(&self) -> &'static str;
    #[allow(dead_code)]
    fn description(&self) -> &'static str;
    fn required_level(&self) -> Level;
    async fn execute(&self, client: &Arc<Client>, state: &Arc<AppState>, args: Vec<&str>) -> Result<()>;
}

pub struct CommandRegistry {
    commands: HashMap<String, Box<dyn Command>>,
}

impl CommandRegistry {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
        }
    }

    pub fn register(&mut self, cmd: Box<dyn Command>) {
        self.commands.insert(cmd.name().to_string(), cmd);
    }

    pub fn get(&self, name: &str) -> Option<&Box<dyn Command>> {
        self.commands.get(name)
    }

    #[allow(dead_code)]
    pub fn get_all(&self) -> Vec<&Box<dyn Command>> {
        self.commands.values().collect()
    }
}
