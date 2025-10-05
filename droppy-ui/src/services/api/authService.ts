import { apiService } from './apiService';
import { clearUser, storeUser, getStoredUser, type User } from './userService';

// Custom error type for authentication errors
class AuthError extends Error {
  status?: number;
  data?: any;
  
  constructor(message: string, status?: number, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

// Module state
let authCheck: Promise<boolean> | null = null;

// Public API
export const clearAuthData = (): void => {
  clearUser();
  authCheck = null;
};

export const login = async (email: string, password: string): Promise<User> => {
  try {
    // First, clear any existing auth state
    clearUser();
    
    // Make the login request
    const response = await apiService.post<{ user: User }>(
      '/api/auth/login/',
      { email, password },
      { 
        withCredentials: true, 
        skipAuth: true 
      }
    );
    
    if (response.data?.user) {
      // Store the user data
      storeUser(response.data.user);
      
      // Verify the session is actually established by making an auth check
      try {
        const isAuth = await isAuthenticated();
        if (!isAuth) {
          throw new Error('Session not established after login');
        }
      } catch (err) {
        console.error('Session verification failed:', err);
        throw new Error('Failed to establish session after login');
      }
      
      return response.data.user;
    }
    
    throw new Error('Invalid response from server');
  } catch (error) {
    let errorMessage = 'Login failed. Please try again.';
    console.log(error);
    
    if (error && typeof error === 'object' && 'response' in error) {
      const err = error as { response?: { status?: number; data?: any } };
      // Handle 400 Bad Request (invalid credentials)
      if (err.response?.status === 400) {
        errorMessage = err.response.data?.error || 'Invalid email or password.';
      }
      // Handle 403 Forbidden (inactive account)
      else if (err.response?.status === 403) {
        errorMessage = 'This account is inactive.';
      }
    } else {
      errorMessage = 'Unable to connect to the server. Please check your connection.';
    }
    
    throw new AuthError(
      errorMessage,
      error && typeof error === 'object' && 'response' in error 
        ? (error as any).response?.status 
        : undefined,
      error && typeof error === 'object' && 'response' in error 
        ? (error as any).response?.data 
        : undefined
    );
  }
};

export const logout = async (): Promise<void> => {
  try {
    await apiService.post(
      '/api/auth/logout/',
      {},
      { 
        withCredentials: true, 
        skipAuth: true 
      }
    );
  } catch (error) {
    console.error('Logout error:', error);
  } finally {
    clearAuthData();
  }
};

export const isAuthenticated = async (): Promise<boolean> => {
  if (authCheck) return authCheck;

  authCheck = (async (): Promise<boolean> => {
    try {
      const storedUser = getStoredUser();
      if (!storedUser) return false;
      
      const response = await apiService.get<{ isAuthenticated: boolean; user: User }>('/api/auth/check-auth/');
      
      if (response.data?.isAuthenticated && response.data.user) {
        // Update stored user data in case it changed
        storeUser(response.data.user);
        return true;
      }
      
      return false;
    } catch (error) {
      // If we get a 401, the session is invalid
      if (error instanceof AuthError && error.status === 401) {
        clearAuthData();
      } else if (error && typeof error === 'object' && 'status' in error && error.status === 401) {
        clearAuthData();
      }
      return false;
    } finally {
      // Reset the auth check after a short delay to allow for retries
      setTimeout(() => { authCheck = null; }, 1000);
    }
  })();

  return authCheck;
};

export const getCurrentUser = (): User | null => {
  return getStoredUser();
};
