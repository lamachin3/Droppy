import { useEffect, useState } from 'react';
import { Button, TextField, Box, Card, CardContent, Typography, Alert, useTheme, alpha, Link } from '@mui/material';
import { useNavigate, useLocation } from 'react-router-dom';
import { login, isAuthenticated } from '@/services/api/authService';


export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();

  useEffect(() => {
    const checkAuth = async () => {
      try {
        const authenticated = await isAuthenticated();
        
        if (authenticated) {
          const from = location.state?.from?.pathname || '/';
          navigate(from, { replace: true });
        }
      } catch (error) {
        console.error('Authentication check failed:', error);
      } finally {
        setLoading(false);
      }
    };
    
    checkAuth();
  }, [location]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!email.trim() || !password.trim()) {
      setError('Please fill in both email and password fields.');
      return;
    }
    
    setLoading(true);
    setError('');

    try {
      const from = (location.state as any)?.from?.pathname || '/';
      
      await login(email, password);
      
      navigate(from, { replace: true, state: { from: location.state?.from } });
    } catch (err: any) {
      let errorMessage = 'Login failed. Please try again.';
      
      if (err.response) {
        if (err.response.status === 400) {
          errorMessage = 'Invalid email or password.';
        } else if (err.response.status === 403) {
          errorMessage = 'Account is inactive or needs verification.';
        } else if (err.response.data?.non_field_errors) {
          errorMessage = err.response.data.non_field_errors.join(' ');
        }
      } else if (err.request) {
        errorMessage = 'Unable to connect to the server. Please check your connection.';
      }
      
      setError(errorMessage);
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  return !loading ? (
    <Box
      sx={{
        minHeight: '100vh',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: theme.palette.background.default,
        padding: 2,
      }}
    >
      <Card
        elevation={0}
        sx={{
          maxWidth: 400,
          width: '100%',
          padding: 3,
          borderRadius: 2.5,
          border: '0.1px solid',
          borderColor: alpha(theme.palette.background.paper, 0.2),
          backgroundColor: theme.palette.background.paper,
        }}
      >
        <CardContent>
          <Typography
            variant="h4"
            component="h1"
            gutterBottom
            sx={{
              textAlign: 'center',
              color: theme.palette.primary.main,
              fontFamily: theme.typography.fontFamily,
              fontWeight: 600,
              mb: 3,
            }}
          >
            Welcome to Droppy
          </Typography>

          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              fullWidth
              margin="normal"
              required
              variant="outlined"
            />
            <TextField
              label="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              fullWidth
              margin="normal"
              required
              variant="outlined"
            />

            {error && (
              <Alert 
                severity="error" 
                sx={{ 
                  mt: 2,
                  fontFamily: theme.typography.fontFamily,
                  alignItems: 'center',
                }}
              > 
                {error}
              </Alert>
            )}

            <Button
              type="submit"
              variant="contained"
              color="primary"
              fullWidth
              disabled={loading}
              sx={{ mt: 3, mb: 2, py: 1.5 }}
            >
              {loading ? 'Signing in...' : 'Sign In'}
            </Button>

            <Box sx={{ textAlign: 'center', mt: 2 }}>
              <Button
                component={Link}
                href="/register"
                variant="text"
                color="primary"
                fullWidth
                sx={{ 
                  py: 1,
                  color: theme.palette.primary.main,
                  textDecoration: 'none',
                  fontFamily: theme.typography.fontFamily,
                  '&:hover': {
                    textDecoration: 'underline',
                  },
                }}
              >
                Create an account
              </Button>
            </Box>
          </Box>
        </CardContent>
      </Card>
    </Box>
  ) : null ;
}
