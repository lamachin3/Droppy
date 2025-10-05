import { Controller, useFormContext } from 'react-hook-form';
import { Box, FormControl, FormControlLabel, FormGroup, MenuItem, Typography, useTheme } from '@mui/material';
import { Icon } from '@iconify/react';
import { FormCheckbox, FormSelect, PanelCard } from '@/components';
import type { ModuleGroup } from './types';


interface AdvancedFeaturesProps {
  modules: ModuleGroup[];
}

export default function AdvancedFeatures({ 
  modules, 
}: AdvancedFeaturesProps) {
  const theme = useTheme();
  const { control } = useFormContext();

  const formatModuleName = (name: string): string =>
    name
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');

  return (
    <PanelCard
      icon={<Icon icon="solar:settings-linear" width="28" height="28" color={theme.palette.primary.contrastText} />}
      title="Select Features"
    >
      {modules.map((group) => {
        const isSelect = group.options.length > 2;

        return (
          <Box key={group.name} sx={{ mb: 1.5 }}>
            <Typography variant="subtitle2" sx={{ mb: 1, fontWeight: 600 }}>
              {formatModuleName(group.name) + (group?.required ? ' *' : '')}
            </Typography>

            {isSelect ? (
              <Controller
                name={group.name}
                control={control}
                defaultValue=""
                render={({ field, fieldState }) => (
                  <FormControl
                    fullWidth
                    error={!!fieldState.error}
                  >
                    {fieldState.error && (
                      <Typography color="error" variant="caption">
                        {fieldState.error.message}
                      </Typography>
                    )}
                    <FormSelect
                      {...field}
                      displayEmpty
                      inputProps={{ 'aria-label': `${group.name} select` }}
                    >
                      <MenuItem value="" disabled>
                        Select an option
                      </MenuItem>
                      {group.options.map((option) => (
                        <MenuItem key={option.value} value={option.value}>
                          {option.label}
                        </MenuItem>
                      ))}
                    </FormSelect>
                  </FormControl>
                )}
              />
            ) : (
              <Controller
                name={group.name}
                control={control}
                defaultValue={[]}
                render={({ field, fieldState }) => (
                  <FormGroup>
                    {fieldState.error && (
                      <Typography color="error" variant="caption">
                        {fieldState.error.message}
                      </Typography>
                    )}
                    {group.options.map((option) => (
                      <FormControlLabel
                        key={option.value}
                        control={
                          <FormCheckbox
                            checked={Array.isArray(field.value) && field.value.includes(option.value)}
                            onChange={(e: any) => {
                              const newValue = e.target.checked
                                ? [...field.value, option.value]
                                : field.value.filter((v: string) => v !== option.value);
                              field.onChange(newValue);
                            }}
                          />
                        }
                        label={option.label}
                        sx={{ py: 0.5 }}
                      />
                    ))}
                  </FormGroup>
                )}
              />
            )}
          </Box>
        );
      })}
    </PanelCard>
  );
}