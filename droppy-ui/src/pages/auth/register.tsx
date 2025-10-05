import { useState } from 'react';
import { Box, Card, CardContent, Typography, Alert, useTheme, alpha, Link } from '@mui/material';
import { useForm, type SubmitHandler, FormProvider } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import * as yup from 'yup';
import { useNavigate } from 'react-router-dom';
import { registerUser } from '@/services/api/userService';
import { CardButton, FormTextField } from '@/components';


interface RegisterFormData {
  email: string;
  username: string;
  password: string;
  password2: string;
}

const schema = yup.object().shape({
  email: yup.string().email('Must be a valid email').required('Email is required'),
  username: yup.string().required('Username is required'),
  password: yup
    .string()
    .min(6, 'Password must be at least 6 characters')
    .required('Password is required'),
    password2: yup
    .string()
    .oneOf([yup.ref('password')], 'Passwords must match')
    .required('Confirm Password is required'),
});

export default function Register() {
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const theme = useTheme();

  const methods = useForm<RegisterFormData>({
    resolver: yupResolver(schema),
    defaultValues: {
      email: '',
      username: '',
      password: '',
      password2: '',
    },
  });

  const { handleSubmit, formState: { errors } } = methods;

  const onSubmit: SubmitHandler<RegisterFormData> = async (data) => {
    setLoading(true);
    try {
      await registerUser(data);
      navigate('/');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
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
              color: theme.palette.text.primary,
              fontFamily: theme.typography.fontFamily,
              fontWeight: 600,
              mb: 3,
            }}
          >
            Create Account
          </Typography>

          <FormProvider {...methods}>
            <Box component="form" onSubmit={handleSubmit(onSubmit)} sx={{ mt: 2 }}>
            <FormTextField
              name="email"
              fullWidth
              label="Email"
              type="email"
              margin="normal"
            />

            <FormTextField
              name="username"
              fullWidth
              label="Username"
              margin="normal"
            />

            <FormTextField
              name="password"
              fullWidth
              type="password"
              label="Password"
              margin="normal"
            />

            <FormTextField
              name="password2"
              fullWidth
              type="password"
              label="Confirm Password"
              margin="normal"
            />

            {(error || Object.keys(errors).length > 0) && (
              <Alert 
                severity="error" 
                sx={{ 
                  mt: 2,
                  fontFamily: theme.typography.fontFamily,
                }}
              >
                {error || 'Please fix the errors in the form'}
              </Alert>
            )}

            <CardButton
              type="submit"
              disabled={loading}
              sx={{ 
                mt: 3, 
                width: '100%',
                fontFamily: theme.typography.fontFamily,
              }}
            >
              {loading ? 'Creating Account...' : 'Create Account'}
            </CardButton>

            <Box sx={{ textAlign: 'center', mt: 2 }}>
              <Typography 
                variant="body2" 
                sx={{ 
                  color: theme.palette.text.secondary,
                  fontFamily: theme.typography.fontFamily,
                }}
              >
                Already have an account?{' '}
                <Link
                  component="button"
                  type="button"
                  onClick={() => navigate('/login')}
                  sx={{
                    color: theme.palette.primary.main,
                    textDecoration: 'none',
                    fontFamily: theme.typography.fontFamily,
                    '&:hover': {
                      textDecoration: 'underline',
                    },
                  }}
                >
                  Sign in
                </Link>
              </Typography>
            </Box>
            </Box>
          </FormProvider>
        </CardContent>
      </Card>
    </Box>
  );
}
