export interface FormConfig {
    features: ModuleGroup[];
    options: CheckboxOption[];
    output: ModuleGroup[];
}

export interface CheckboxOption {
    value: string;
    label: string;
    tooltip?: string;
    checked?: boolean;
    enabled?: boolean;
    conditional?: boolean;
}

export interface SelectOption {
    value: string;
    label: string;
}

export interface FileExtension {
    value: string;
    label: string;
}

export interface ModuleGroup {
    name: string;
    options: CheckboxOption[];
    label?: string;
    required?: boolean;
    description?: string;
}

export interface AdvancedFeaturesProps {
    modules: ModuleGroup[];
    handleModuleChange: (groupId: number, optionId: string, checked: boolean) => void;
}

export interface AdvancedOptionsProps {
    formOptions: CheckboxOption[];
    options: CheckboxOption[];
    injectors: Object[];
}

export interface AdvancedOutputProps {
    fileExtensions: FileExtension[];
}
