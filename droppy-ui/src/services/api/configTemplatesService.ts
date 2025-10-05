import { apiService } from './apiService';

const API_BASE_URL = '/api/dropper/dropper_templates/';


/**
 * Toggles the state of a dropper template
 * @param id The ID of the template to toggle
 * @returns Promise with the toggle result
 * @throws {Error} If the request fails
 */
export const toggleTemplateState = async (id: string): Promise<any> => {
    try {
        const response = await apiService.post(`${API_BASE_URL}${id}/toggle/`);
        return response.data;
    } catch (error) {
        console.error('Failed to toggle template:', error);
        throw error;
    }
}

/**
 * Fetches a list of all dropper templates
 * @returns Promise with the list of templates
 * @throws {Error} If the request fails
 */
export const listTemplates = async (): Promise<any> => {
    try {
        const response = await apiService.get(API_BASE_URL);
        return response.data;
    } catch (error) {
        console.error('Failed to fetch templates:', error);
        throw error;
    }
}

/**
 * Renames a dropper template
 * @param id The ID of the template to rename
 * @param name The new name for the template
 * @returns Promise with the rename result
 * @throws {Error} If the request fails
 */
export const renameTemplate = async (id: string, name: string): Promise<any> => {
    try {
        const response = await apiService.post(`${API_BASE_URL}${id}/rename/`, { name });
        return response.data;
    } catch (error) {
        console.error('Failed to rename template:', error);
        throw error;
    }
}

/**
 * Downloads a dropper template
 * @param id The ID of the template to download
 * @returns Promise with the download result
 * @throws {Error} If the request fails
 */
export const downloadTemplate = async (id: string): Promise<any> => {
    try {
        const response = await apiService.get(`${API_BASE_URL}${id}/download/`);
        return response.data;
    } catch (error) {
        console.error('Failed to download template:', error);
        throw error;
    }
}

/**
 * Uploads a dropper template JSON file
 * @param file The file to upload
 * @returns Promise with the upload result
 * @throws {Error} If the request fails
 */
export const uploadTemplate = async (file: File): Promise<any> => {
    try {
        const formData = new FormData();
        formData.append('file', file);
        const response = await apiService.post(API_BASE_URL, formData, {
            headers: {
                'Content-Type': 'multipart/form-data'
            }
        });
        return response.data;
    } catch (error) {
        console.error('Failed to upload template:', error);
        throw error;
    }
}
