import * as yup from 'yup';
import { type FormConfig } from './types';


export function buildSchemaFromConfig(config: FormConfig) {
    // helper: checks arrays and strings for non-empty values
    const requiredCheck = (message: string) =>
        yup.mixed().test('required-dynamic', message, (value) => {
            if (value == null) return false;
            if (Array.isArray(value)) return value.length > 0;
            if (typeof value === 'string') return value.trim().length > 0;
            // allow other truthy values
            return !!value;
        }
    );
  
    const shape: Record<string, any> = {};
  
    // If features is an array of feature descriptors
    if (Array.isArray(config.features)) {
        for (const feat of config.features) {
            const name = feat.name;
            if (!name) continue;
            if (feat.required) {
            // accept either a string (single select) or array (multi-select)
            shape[name] = requiredCheck(`${feat.name} is required`);
            } else {
            // optional
            shape[name] = yup.mixed().nullable();
            }
        }
    } else if (config.features && typeof config.features === 'object') {
        // if features is a keyed object instead of array (flexible)
        for (const [name, feat] of Object.entries(config.features)) {
            if ((feat as any).required) {
            shape[name] = requiredCheck(`${name} is required`);
            } else {
            shape[name] = yup.mixed().nullable();
            }
        }
    }
  
    // Additional standard fields you'd like validated:
    shape.outputFilename = yup.string().required('Output filename is required');
    shape.outputExtension = yup.string().required('Output extension is required');
  
    // Input sources: uploadedShellcode (array), rawShellcode (string), githubPayload (string)
    shape.uploadedShellcode = yup.array().of(yup.mixed()).nullable();
    shape.rawShellcode = yup.string().nullable();
    shape.githubPayload = yup.string().nullable();
  
    // root schema (use .test for cross-field "at least one input" rule)
    let schema = yup.object().shape(shape);
    schema = schema.test(
        'at-least-one-input',
        'Provide at least one input: file, raw shellcode, or GitHub URL',
        function (value) {
            if (!value) return this.createError({ path: 'inputField', message: 'Provide at least one input: file, raw shellcode, or GitHub URL' });
        
            const hasFile = Array.isArray(value.uploadedShellcode) && value.uploadedShellcode.length > 0;
            const hasText = typeof value.rawShellcode === 'string' && value.rawShellcode.trim().length > 0;
            const hasGithub = typeof value.githubPayload === 'string' && value.githubPayload.trim().length > 0;
        
            if (!(hasFile || hasText || hasGithub)) {
                // Attach error to "inputField" (or any field you want)
                return this.createError({
                path: 'inputField',
                message: 'Provide at least one input: file, raw shellcode, or GitHub URL'
                });
            }
      
          return true; // valid
        }
    );
  
    return schema;
  }