import { Icon } from '@iconify/react';
import { Typography, useTheme } from '@mui/material';
import { FormTextField, FormAutocomplete, FormDropzone, SlidingTab, PanelCard } from '@/components';
import { useEffect, useState } from 'react';
import { useFormContext, useWatch } from 'react-hook-form';


interface AdvancedInputProps {
    github_executables: Array<{ filename: string, url: string }>;
}

export default function AdvancedInput({ github_executables }: AdvancedInputProps) {
    const theme = useTheme();
    const { control, formState: { errors } } = useFormContext();

    const [activeTab, setActiveTab] = useState('file_upload');
    const uploadedShellcode = useWatch({ name: "uploadedShellcode", control });
    const githubPayload = useWatch({ name: "githubPayload", control });

    useEffect(() => {
        setActiveTab('file_upload');
    }, []);

    const handleTabChange = (tabId: string) => {
        setActiveTab(tabId);
    };

    const tabs = [
        { 
            id: 'file_upload', 
            icon: 'solar:code-file-linear', 
            label: 'File Upload', 
            content: (
                <>
                    <FormDropzone
                        name="uploadedShellcode"
                        multiple={false}
                        showPreview={true}
                    />
                    {uploadedShellcode?.length > 0 && (
                        <FormTextField
                            name="executionArgs"
                            label="Execution arguments"
                            sx={{ mt: 2 }}
                            placeholder="--help"
                        />
                    )}
                </>
            )
        },
        { 
            id: 'manual_input', 
            icon: 'solar:pen-new-round-linear', 
            label: 'Manual Input', 
            content: (
                <FormTextField
                    name="rawShellcode"
                    label="Shellcode"
                    multiline
                    rows={10}
                    autoFocus={true}
                    formatIndicator="Hex format"
                    placeholder="Enter shellcode in hex format...
            
Example:
\x90\x90\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
                />
            )
        },
        { 
            id: 'github',
            icon: 'mdi:github',
            label: 'GitHub',
            content: (
                <>
                    <FormAutocomplete 
                        name="githubPayload"
                        label="Github Tool or URL"
                        autoFocus={true}
                        placeholder="Executable name (e.g. mimikatz.exe) or GitHub URL"
                        options={github_executables.map(item => ({
                            label: item.filename,
                            value: item.url
                        }))}
                    />
                    {githubPayload?.length > 0 && (
                        <FormTextField
                            name="executionArgs"
                            label="Execution arguments"
                            sx={{ mt: 2 }}
                            placeholder="--help"
                        />
                    )}
                </>
            )
        }
    ];
    
    return (
        <PanelCard
            icon={<Icon icon="solar:code-square-linear" width="28" height="28" color={theme.palette.primary.contrastText} />}
            title="Payload Input"
        >
            {errors.inputField && (
                <Typography sx={{ color: theme.palette.error.main, mb: 1 }} variant="body2">
                    {errors.inputField.message}
                </Typography>
            )}
            <SlidingTab
                tabs={tabs}
                defaultTab={activeTab}
                onChange={handleTabChange}
            />
        </PanelCard>
    );
}