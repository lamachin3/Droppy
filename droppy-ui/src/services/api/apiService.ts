import axios, { type AxiosInstance, type AxiosRequestConfig, type InternalAxiosRequestConfig } from 'axios';

export interface ApiResponse<T = any> {
  data: T;
  status: number;
  statusText: string;
  headers: any;
}

export interface ApiError {
  message: string;
  status?: number;
  data?: any;
}

export interface RequestOptions extends AxiosRequestConfig {
  skipAuth?: boolean;
}

class ApiService {
  private static instance: ApiService;
  private api: AxiosInstance;
  private baseURL: string = import.meta.env.VITE_API_URL || 'http://localhost:8000';

  private constructor() {
    this.api = axios.create({
      baseURL: this.baseURL,
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-CSRFToken': '',
      },
      withCredentials: true,
    });

    this.setupInterceptors();
  }

  public static getInstance(): ApiService {
    if (!ApiService.instance) {
      ApiService.instance = new ApiService();
    }
    return ApiService.instance;
  }

  private csrfToken: string | null = null;
  private isRefreshing = false;
  private failedQueue: Array<{
    resolve: (value?: any) => void;
    reject: (error: any) => void;
  }> = [];

  private async getCSRFToken(): Promise<string> {
    if (this.csrfToken) return this.csrfToken;
  
    try {
      const response = await axios.get(`${this.baseURL}/api/auth/csrf/`, {
        withCredentials: true,
      });
  
      const token = response.data?.csrfToken || response.data?.csrf_token;
      if (token) {
        this.csrfToken = token;
        this.api.defaults.headers.common['X-CSRFToken'] = token;
        return token;
      }
      throw new Error('No CSRF token in response');
    } catch (error) {
      console.error('Failed to fetch CSRF token:', error);
      throw error;
    }
  }
  

  private processQueue(error: any, token: string | null = null) {
    this.failedQueue.forEach((promise) => {
      if (error) {
        promise.reject(error);
      } else {
        promise.resolve(token);
      }
    });
    this.failedQueue = [];
  }

  private setupInterceptors(): void {
    // Request interceptor
    this.api.interceptors.request.use(
      async (config: InternalAxiosRequestConfig) => {
        const method = config.method?.toLowerCase();
    
        // Skip CSRF for safe or skipAuth requests
        if (['get', 'head', 'options'].includes(method || '') || (config as any).skipAuth) {
          return config;
        }
    
        // Ensure we have a CSRF token before sending
        if (!this.csrfToken) {
          if (!this.isRefreshing) {
            this.isRefreshing = true;
            try {
              const token = await this.getCSRFToken();
              this.isRefreshing = false;
              this.processQueue(null, token);
            } catch (error) {
              this.processQueue(error, null);
              this.isRefreshing = false;
              return Promise.reject(error);
            }
          } else {
            // Wait if another request is fetching the token
            return new Promise((resolve, reject) => {
              this.failedQueue.push({ resolve, reject });
            }).then(() => {
              config.headers['X-CSRFToken'] = this.csrfToken;
              return config;
            });
          }
        }
    
        // Always attach token if available
        config.headers['X-CSRFToken'] = this.csrfToken;
        return config;
      },
      (error) => Promise.reject(error)
    );    

    // Response interceptor
    this.api.interceptors.response.use(
      (response) => response,
      async (error: any) => {
        const originalRequest = error.config;

        // Handle 403 Forbidden (CSRF token missing or incorrect)
        if (error.response?.status === 403 && !originalRequest._retry) {
          originalRequest._retry = true;
          
          try {
            this.csrfToken = null;
            const token = await this.getCSRFToken();
            originalRequest.headers['X-CSRFToken'] = token;
            return this.api(originalRequest);
          } catch (refreshError) {
            console.error('Failed to refresh CSRF token:', refreshError);
          }
        }

        // Handle 401 Unauthorized (session expired)
        if (error.response?.status === 401) {
          // Redirect to login page if not already there
          if (!window.location.pathname.startsWith('/login')) {
            window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
          }
        }
        
        return Promise.reject(error);
      }
    );
  }

  public async get<T = any>(
    url: string,
    params?: any,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    try {
      const response = await this.api.get<T>(url, {
        ...options,
        params,
      });
      return {
        data: response.data,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      };
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  public async post<T = any>(
    url: string,
    data?: any,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    try {
      await this.getCSRFToken();
      const response = await this.api.post<T>(url, data, options);
      return {
        data: response.data,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      };
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  public async put<T = any>(
    url: string,
    data?: any,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    try {
      await this.getCSRFToken();
      const response = await this.api.put<T>(url, data, options);
      return {
        data: response.data,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      };
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  public async delete<T = any>(
    url: string,
    data?: any,
    options: RequestOptions = {}
  ): Promise<ApiResponse<T>> {
    try {
      await this.getCSRFToken();
      const response = await this.api.delete<T>(url, {
        ...options,
        data,
      });
      return {
        data: response.data,
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      };
    } catch (error: any) {
      throw this.handleError(error);
    }
  }

  private handleError(error: any): ApiError {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      return {
        message: error.response.data?.message || 'An error occurred',
        status: error.response.status,
        data: error.response.data,
      };
    } else if (error.request) {
      // The request was made but no response was received
      return {
        message: 'No response received from server',
      };
    } else {
      // Something happened in setting up the request that triggered an Error
      return {
        message: error.message || 'An error occurred',
      };
    }
  }
}

export const apiService = ApiService.getInstance();
