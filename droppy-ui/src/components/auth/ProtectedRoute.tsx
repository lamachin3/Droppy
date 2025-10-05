import { useEffect, useState } from 'react';
import type { ReactElement } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { isAuthenticated } from '@/services/api/authService';
import { CircularProgress, Box } from '@mui/material';

interface ProtectedRouteProps {
  element: ReactElement;
}

export function ProtectedRoute({ 
  element, 
}: ProtectedRouteProps) {
  const [isAuth, setIsAuth] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    let isMounted = true;

    const checkAuth = async () => {
      try {
        const authenticated = await isAuthenticated();
        
        if (!isMounted) return;
        
        // Only update state if we're not in the middle of a navigation
        if (location.pathname === '/login' && authenticated) {
          const from = location.state?.from?.pathname || '/';
          navigate(from, { replace: true });
        } else if (!authenticated && location.pathname !== '/login') {
          navigate('/login', { 
            replace: true,
            state: { from: location } 
          });
        }
        
        setIsAuth(authenticated);
      } catch (error) {
        console.error('Authentication check failed:', error);
        if (isMounted) {
          setIsAuth(false);
          if (location.pathname !== '/login') {
            navigate('/login', { 
              replace: true,
              state: { from: location } 
            });
          }
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    };

    checkAuth();

    return () => {
      isMounted = false;
    };
  }, [location.pathname, navigate, location]);

  if (isLoading) {
    return (
      <Box
        sx={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '100vh',
        }}
      >
        <CircularProgress />
      </Box>
    );
  }

  return isAuth ? element : null;
}

export default ProtectedRoute;
