pub struct Theme {
    pub primary: u8,
    pub secondary: u8,
    pub accent: u8,
    pub error: u8,
    pub success: u8,
    pub text: u8,
    pub dim: u8,
}

impl Theme {
    pub fn default() -> Self {
        Self {
            primary: 51,   // Cyan
            secondary: 39, // Blue
            accent: 45,    // Light Blue
            error: 196,    // Red
            success: 82,   // Green
            text: 255,     // White
            dim: 245,      // Grey
        }
    }

    pub fn matrix() -> Self {
        Self {
            primary: 46,
            secondary: 40,
            accent: 118,
            error: 196,
            success: 46,
            text: 120,
            dim: 22,
        }
    }
}

pub const CURRENT_THEME: Theme = Theme {
    primary: 51,
    secondary: 39,
    accent: 45,
    error: 196,
    success: 82,
    text: 255,
    dim: 245,
};
