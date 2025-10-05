// Types for features and options
export interface CheckboxOption {
    id: string;
    label: string;
    tooltip?: string;
    checked: boolean;
}

export interface BasicDropperFormData {
    // Features
    injector: boolean;
    loader: boolean;
    obfuscation: boolean;
    amsi_bypass: boolean;
    etw_bypass: boolean;
    unhooking: boolean;
    syscalls: boolean;
    
    // Options
    debug_mode: boolean;
    hide_console: boolean;
    
    // Input
    shellcode_text: string;
    shellcode: File | null;
    github_url: string;
    execution_args: string;
    remote_process_name: string;
    
    // Output
    filename: string;
    file_extension: string;
  }

/* Props */
export type BasicDropperFeaturesProps = {
    features: CheckboxOption[];
    setFeatures: (features: CheckboxOption[]) => void;
    processMode: string;
    setProcessMode: (processMode: string) => void;
    remoteProcess: string;
    setRemoteProcess: (remoteProcess: string) => void;
    obfuscationMode: string;
    setObfuscationMode: (obfuscationMode: string) => void;
};

export type BasicDropperOptionsProps = {
    options: CheckboxOption[];
    setOptions: (options: CheckboxOption[]) => void;
    binarySigning: object | null;
    setBinarySigning: (binarySigning: object | null) => void;
};

export type BasicDropperInputProps = {
    uploadedShellcode: File[];
    setuploadedShellcode: (files: File[]) => void;
    executionArgs: string;
    setExecutionArgs: (args: string) => void;
    rawShellcode: string;
    setRawShellcode: (shellcode: string) => void;
    githubPayload: string;
    setGithubPayload: (payload: string) => void;
};

export type BasicDropperOutputProps = {
    outputFilename: string;
    setOutputFilename: (filename: string) => void;
    outputExtension: string;
    setOutputExtension: (extension: string) => void;
};
