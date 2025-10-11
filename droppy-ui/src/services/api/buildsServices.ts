import type { AxiosProgressEvent } from 'axios';
import { apiService } from './apiService';

// Types
interface BuildMetadata {
  version?: string;
  platform?: string;
  [key: string]: any;
}

export interface Build {
  id: string;
  name: string;
  filename: string;
  size: number;
  created_at: string;
  download_url: string;
  build_type?: string;
  metadata?: BuildMetadata;
}

export interface BuildListResponse {
  count: number;
  results: Build[];
}

type DownloadProgressCallback = (progressEvent: AxiosProgressEvent) => void;
type ErrorCallback = (error: Error) => void;

// Constants
const BUILDS_ENDPOINT = '/api/files/';
const DEFAULT_CONTENT_TYPE = 'application/octet-stream';

/**
 * Extracts filename from Content-Disposition header
 */
const extractFilenameFromHeaders = (headers: Record<string, string>, fallback: string): string => {
  const contentDisposition = headers['content-disposition'] || headers['Content-Disposition'];
  console.log(headers);
  console.log(contentDisposition);
  if (!contentDisposition) return fallback;

  const match = contentDisposition.split(';').find((header) => header.includes('filename='));
  const filename = match?.split('=')[1].replace(/['"]/g, '').trim() || fallback;
  return filename || fallback;
};

/**
 * Triggers file download in the browser
 */
const triggerFileDownload = (blob: Blob, filename: string): void => {
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  
  document.body.appendChild(link);
  link.click();
  
  // Cleanup
  setTimeout(() => {
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  }, 100);
};

/**
 * Fetches a list of all builds
 * @throws {Error} If the request fails
 */
export const listBuilds = async (): Promise<BuildListResponse> => {
    try {
      const { data } = await apiService.get<BuildListResponse>(BUILDS_ENDPOINT);
      return data;
    } catch (error) {
      console.error('Failed to fetch builds:', error);
      throw new Error('Failed to load builds. Please try again later.');
    }
};

  /**
   * Fetches details of a specific build
   * @param buildId - The ID of the build to retrieve
   * @throws {Error} If the build is not found or the request fails
   */
export const getBuild = async (buildId: string): Promise<Build> => {
    try {
      const { data } = await apiService.get<Build>(`${BUILDS_ENDPOINT}${buildId}/`);
      return data;
    } catch (error) {
      console.error(`Failed to fetch build ${buildId}:`, error);
      throw new Error('Build not found or you do not have permission to view it.');
    }
};

  /**
   * Downloads a build file
   * @param buildId - The ID of the build to download
   * @param onProgress - Optional progress callback
   * @param onError - Optional error callback
   */
export const downloadBuild = async (
    buildId: string,
    onProgress?: DownloadProgressCallback,
    onError?: ErrorCallback
  ): Promise<void> => {
    try {
      const response = await apiService.get<ArrayBuffer>(
        `${BUILDS_ENDPOINT}${buildId}/download/`,
        {},
        {
          responseType: 'arraybuffer',
          onDownloadProgress: onProgress,
        }
      );
  
      const blob = new Blob([response.data], {
        type: response.headers['content-type'] || 'application/octet-stream',
      });
      const filename = extractFilenameFromHeaders(response.headers, 'droppy.exe');
      console.log(filename);
  
      triggerFileDownload(blob, filename);
    } catch (error) {
      console.error(`Failed to download build ${buildId}`, error);
      onError?.(error instanceof Error ? error : new Error("Download failed"));
    }
  };

  /**
   * Deletes a build
   * @param buildId - The ID of the build to delete
   * @throws {Error} If the deletion fails
   */
export const deleteBuild = async (buildId: string): Promise<void> => {
    try {
      await apiService.delete(`${BUILDS_ENDPOINT}${buildId}/`);
    } catch (error) {
      console.error(`Failed to delete build ${buildId}:`, error);
      throw new Error('Failed to delete build. Please try again.');
    }
};

  /**
   * Formats file size in a human-readable format
   * @param bytes - File size in bytes
   * @param decimals - Number of decimal places to show (default: 2)
   */
export const formatFileSize = (bytes: number, decimals: number = 2): string => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    const formattedValue = parseFloat((bytes / Math.pow(k, i)).toFixed(decimals < 0 ? 0 : decimals));
    
    return `${formattedValue} ${sizes[i]}`;
  };

  /**
   * Formats a date string to a readable format
   * @param dateString - ISO date string
   * @param locale - Locale string (default: browser's locale)
   */
export const formatDate = (dateString: string, locale: string = navigator.language): string => {
    const options: Intl.DateTimeFormatOptions = {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    };
    
    try {
      return new Date(dateString).toLocaleDateString(locale, options);
    } catch (error) {
      console.error('Error formatting date:', error);
      return dateString; // Return original string if formatting fails
    }
};
