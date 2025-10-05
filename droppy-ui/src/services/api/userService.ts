import { apiService } from "./apiService";

// Types
export interface User {
  id: string;
  email: string;
  firstname?: string;
  lastname?: string;
  is_staff?: boolean;
  is_active?: boolean;
  date_joined?: string;
  groups?: string[];
}

export interface RegisterFormData {
    email: string;
    username: string;
    password: string;
    confirmPassword: string;
}

// Constants
const USER_KEY = 'user_data';

// Module state
let currentUser: User | null = null;

// Internal functions
export const storeUser = (user: User): void => {
  currentUser = user;
  localStorage.setItem(USER_KEY, JSON.stringify(user));};

export const clearUser = (): void => {
  currentUser = null;
  localStorage.removeItem(USER_KEY);
  // Clear any session cookies by setting an expired cookie
  document.cookie = 'sessionid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
};

export const getStoredUser = (): User | null => {
  if (currentUser) return currentUser;
  const userData = localStorage.getItem(USER_KEY);
  return userData ? JSON.parse(userData) : null;
};

export const getCurrentUser = (): User | null => {
  return getStoredUser();
};

export const registerUser = async (registerData: RegisterFormData): Promise<User> => {
  try {
    const response = await apiService.post<{ user: User }>(
      '/api/users/register/',
      registerData
    );
    const user = response.data.user;
    storeUser(user);
    return user;
  } catch (error) {
    throw error;
  }
};