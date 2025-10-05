import * as yup from 'yup';
import { type BasicDropperFormData } from './types';

export function buildSchemaFromConfig() {
    // Define the base shape of the schema
    const shape: Record<string, any> = {
        // Features - all are optional booleans with default false
        local_injection: yup.boolean().default(false),
        remote_injection: yup.boolean().default(false),
        loader: yup.boolean().default(false),
        obfuscation: yup.boolean().default(false),
        amsi_bypass: yup.boolean().default(false),
        etw_bypass: yup.boolean().default(false),
        unhooking: yup.boolean().default(false),
        syscalls: yup.boolean().default(false),
        
        // Options
        debug_mode: yup.boolean().default(false),
        hide_console: yup.boolean().default(false),
        redirect_output: yup.boolean().default(false),
        remote_process_name: yup.string().nullable(),
        
        // Input
        shellcode_text: yup.string().nullable(),
        shellcode: yup.mixed<File | null>().nullable(),
        github_url: yup.string().url('Must be a valid URL').nullable(),
        execution_args: yup.string().nullable(),
        
        // Output
        filename: yup
            .string()
            .required('Filename is required')
            .matches(
                /^[a-zA-Z0-9_\-\.]+$/,
                'Filename can only contain letters, numbers, underscores, hyphens, and dots'
            ),
        file_extension: yup
            .string()
            .required('File extension is required')
            .oneOf(['.exe'], 'Only .exe extension is supported')
    };

    // Create base schema
    let schema = yup.object().shape(shape);

    // Add validation so that at least one injection technique is selected
    schema = schema.test(
        'at-least-one-injection',
        'You must select at least one injection technique',
        function (value: BasicDropperFormData) {
            if (!value) return false;
            
            const hasLocalInjection = value.local_injection;
            const hasRemoteInjection = value.remote_injection;
            
            if (!(hasLocalInjection || hasRemoteInjection)) {
                return this.createError({
                    path: 'injectionTechnique',
                    message: 'You must select at least one injection technique'
                });
            }
            return true;
        }
    );

    // Add validation for at least one input method
    schema = schema.test(
        'at-least-one-input',
        'You must provide at least one input method (file, manual input or GitHub URL)',
        function (value: BasicDropperFormData) {
            if (!value) return false;
            
            const hasFile = Array.isArray(value.uploadedShellcode) && value.uploadedShellcode.length > 0;
            const hasText = typeof value.rawShellcode === 'string' && value.rawShellcode.trim().length > 0;
            const hasGithub = typeof value.githubPayload === 'string' && value.githubPayload.trim().length > 0;
            
            if (!(hasText || hasFile || hasGithub)) {
                return this.createError({
                    path: 'inputField',
                    message: 'You must provide at least one input method (text, file, or GitHub URL)'
                });
            }
            return true;
        }
    );

    return schema;
}

export const basicDropperSchema = buildSchemaFromConfig();

// Type for the form values
export type BasicDropperFormValues = yup.InferType<ReturnType<typeof buildSchemaFromConfig>>;

// Default form values
export const defaultBasicDropperValues: BasicDropperFormValues = {
  // Features
  injector: '',
  loader: '',
  obfuscation: '',
  amsi_bypass: '',
  etw_bypass: '',
  unhooking: '',
  syscalls: '',
  
  // Options
  debug_mode: false,
  hide_console: false,
  redirect_output: false,
  remote_process_name: '',
  
  // Input
  shellcode_text: '',
  shellcode: null,
  github_url: '',
  execution_args: '',
  
  // Output
  filename: 'dropper',
  file_extension: '.exe',
};