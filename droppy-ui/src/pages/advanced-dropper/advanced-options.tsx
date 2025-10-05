import { Controller, useFormContext } from "react-hook-form";
import { Icon } from "@iconify/react";
import { Box, FormGroup, useTheme, FormControlLabel } from "@mui/material";
import { FormCheckbox, FormTextField, SlidingTab, PanelCard } from "@/components";
import type { AdvancedOptionsProps } from "./types";


export default function AdvancedOptions({ formOptions, options, injectors }: AdvancedOptionsProps) {
    const theme = useTheme();
    const { control, watch } = useFormContext();

    const binarySigning = watch("binary_signing");
    const injector = watch("injector");

    return (
        <PanelCard
            icon={<Icon icon="solar:settings-linear" width="28" height="28" color={theme.palette.primary.contrastText} />}
            title="Global Options"
            sx={{ mt: 2 }}
        >
            <Box>
                <FormGroup>
                    {formOptions?.map((option) =>  !option.conditional ? (
                        <Controller
                            key={option.value}
                            name={option.value}
                            control={control}
                            defaultValue={false}
                            render={({ field }) => (
                                <FormControlLabel
                                    key={option.value}
                                    control={
                                        <FormCheckbox
                                            {...field}
                                            checked={!!field.value}
                                        />
                                    }
                                    label={option.label}
                                />
                            )}
                        />
                    ) : null )}
                    {(injector && injectors.some((i) => i.value === injector && i.label.toLowerCase().includes('remote'))) && (
                        <Controller
                            key="remote_process_name"
                            name="remote_process_name"
                            control={control}
                            defaultValue=""
                            render={({ field }) => (
                                <FormTextField
                                    {...field}
                                    label="Remote Process Name"
                                    sx={{ mt: 2 }}
                                    placeholder="runtimebroker.exe"
                                />
                            )}
                        />
                    )}
                    {binarySigning && (
                        <SlidingTab
                            sx={{ mt: 2 }}
                            tabs={[
                                { id: 'certificate', icon: 'solar:download-linear', label: 'Import', content: 
                                    <>
                                        <FormTextField
                                            label="Certificate"
                                            value={options.find((option) => option.value === 'signing_certificate')?.value}
                                            sx={{ mt: 2 }}
                                            placeholder="Enter certificate"
                                            onChange={(event) => console.log(event.target.value)}
                                        />
                                    </>
                                },
                                { id: 'github', icon: 'mdi:github', label: 'GitHub', content: 
                                    <>
                                        <FormTextField
                                            label="GitHub"
                                            value={options.find((option) => option.value === 'signing_certificate')?.value}
                                            sx={{ mt: 2 }}
                                            placeholder="Enter GitHub"
                                            onChange={(event) => console.log(event.target.value)}
                                        />
                                    </>
                                },
                                { id: 'self_signed', icon: 'solar:pen-new-square-linear', label: 'Self Signed', content: 
                                    <>
                                        <FormTextField
                                            label="Self Signed"
                                            value={options.find((option) => option.value === 'signing_certificate')?.value}
                                            sx={{ mt: 2 }}
                                            placeholder="Enter self signed"
                                            onChange={(event) => console.log(event.target.value)}
                                        />
                                    </>
                                }
                            ]}
                        />
                    )}
                </FormGroup>
            </Box>
        </PanelCard>
    )
}