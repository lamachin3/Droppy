import { apiService } from './apiService';

const API_BASE_URL = '/api/dropper';

export interface DropperOption {
  value: string;
  display: string;
}

export interface DropperOptions {
  features: DropperOption[];
  options: DropperOption[];
  input: {
    github: string[];
  };
  output: DropperOption[];
}

/**
 * Fetches available dropper configuration options
 * @returns Promise with dropper options
 * @throws {ApiError} If the request fails
 */
export const getAdvancedDropperOptions = async (): Promise<DropperOptions> => {
  try {
    const response = await apiService.get<DropperOptions>(`${API_BASE_URL}/advanced/`);
    return response.data;
  } catch (error) {
    console.error('Error fetching dropper options:', error);
    throw error;
  }
};

export const buildDropper = async (payload: any): Promise<any> => {
  try {
    const response = await apiService.post<any>(`${API_BASE_URL}/build/`, payload);
    return response.data;
  } catch (error) {
    console.error('Error building dropper:', error);
    throw error;
  }
};


export interface BasicDropperFormOptions {
  features: Array<{
    name: string;
    required: boolean;
    description: string;
  }>;
  options: Array<{
    name: string;
    description: string;
  }>;
  input: {
    github: string[];
  };
  output: Array<{
    name: string;
    description: string;
    default?: string;
  }>;
}

/**
 * Get basic dropper configuration options
 * @returns Promise with basic dropper options
 * @throws {ApiError} If the request fails
 */
export const getBasicDropperOptions = async (): Promise<BasicDropperFormOptions> => {
  try {
    const response = await apiService.get<BasicDropperFormOptions>(`${API_BASE_URL}/basic/`);
    return response.data;
  } catch (error) {
    console.error('Error fetching basic dropper options:', error);
    throw error;
  }
};

/**
 * Build a basic dropper
 * @param formData Form data for the basic dropper
 * @returns Promise with the build result
 * @throws {ApiError} If the request fails
 */
export const buildBasicDropper = async (formData: FormData): Promise<{ task_id: string }> => {
  try {
    const response = await apiService.post<{ task_id: string }>(
      `${API_BASE_URL}/basic/`,
      formData,
      {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      }
    );
    return response.data;
  } catch (error) {
    console.error('Error building basic dropper:', error);
    throw error;
  }
};