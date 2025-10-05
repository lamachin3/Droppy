import { Box, useTheme, FormGroup, FormControlLabel, Tooltip } from '@mui/material';
import { FormCheckbox, PanelCard } from '@/components';
import { Icon } from '@iconify/react';
import { Controller, useFormContext } from 'react-hook-form';
import type { ModuleGroup } from '../advanced-dropper/types';


interface BasicFeaturesProps {
    features: ModuleGroup[];
}

export default function BasicDropperFeatures({ features }: BasicFeaturesProps) {
    const theme = useTheme();
    const { control, setValue } = useFormContext();

    const concurrent_features: [string, string][] = [
        ['local_injection', 'remote_injection'],
    ];

    const handleFeatureChange = (feature: string, checked: boolean) => {
        const pair = concurrent_features.find(([a, b]) => a === feature || b === feature);
        if (pair && checked) {
            const other = pair[0] === feature ? pair[1] : pair[0];
            setValue(other, false);
        }
    };

    return (
        <PanelCard
            icon={<Icon icon="solar:settings-linear" width="28" height="28" color={theme.palette.primary.contrastText} />}
            title="Select Features"
        >
            <Box>
                <FormGroup>
                    {features?.map((feature) => (
                        <Controller
                            key={feature.name}
                            name={feature.name}
                            control={control}
                            render={({ field }) => (
                                <Tooltip key={feature.name} title={feature.description} enterDelay={500}>
                                    <FormControlLabel
                                        control={
                                            <FormCheckbox 
                                                {...field}
                                                name={feature.name}
                                                control={control}
                                                checked={!!field.value}
                                                onChange={(checked) => {
                                                    field.onChange(checked);
                                                    handleFeatureChange(feature.name, checked);
                                                }}
                                            />
                                        }
                                        label={feature.label}
                                    />
                                </Tooltip>
                            )}
                        />
                    ))}
                </FormGroup>
            </Box>
        </PanelCard>
    );
}
