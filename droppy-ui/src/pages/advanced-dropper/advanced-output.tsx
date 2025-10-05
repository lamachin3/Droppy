import { Icon } from "@iconify/react";
import { FormSelectTextField, SubmitButton, PanelCard } from "@/components";
import { useTheme } from "@mui/material";
import type { AdvancedOutputProps } from "./types";


export default function AdvancedOutput({
    fileExtensions,
}: AdvancedOutputProps) {
    const theme = useTheme();
    
    return (
        <PanelCard
            icon={<Icon icon="solar:tuning-square-outline" width="28" height="28" color={theme.palette.primary.contrastText} />}
            title="Output Settings"
            sx={{ mt: 2 }}
        >
            <FormSelectTextField
                filenameField="outputFilename"
                extensionField="outputExtension"
                label="Output Filename"
                placeholder="dropper"
                extensions={fileExtensions.map(ext => ext.value)}
            />
            
            <SubmitButton
                sx={{ mt: 2, width: '100%' }}
            >
                <Icon icon="solar:rocket-2-linear" width="20" height="20" style={{ marginRight: '8px' }} />
                Build Dropper
            </SubmitButton>
        </PanelCard>
    )
}