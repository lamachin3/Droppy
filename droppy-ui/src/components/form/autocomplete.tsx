import { useState } from "react";
import { Controller, useFormContext } from "react-hook-form";
import { alpha, Autocomplete as MuiAutocomplete, TextField, useTheme, type AutocompleteProps } from "@mui/material";
import { Icon } from '@iconify/react';

export interface AutocompleteOption {
    label: string;
    value: string;
}

interface BaseAutocompleteProps extends Omit<AutocompleteProps<AutocompleteOption | string, false, false, false>, 'renderInput'> {
    options: (AutocompleteOption | string)[];
    label: string;
    placeholder?: string;
    autoFocus?: boolean;
    error?: boolean;
    helperText?: string;
    value?: any;
    onChange?: (value: any) => void;
}

const BaseAutocomplete = ({
    options,
    label,
    placeholder,
    autoFocus = false,
    error = false,
    helperText,
    value,
    onChange,
    ...props
}: BaseAutocompleteProps) => {
    const theme = useTheme();
    const [inputValue, setInputValue] = useState("");

    const clearIconNode = (
        <Icon
            icon="solar:x-circle-linear"
            width={20}
            height={20}
            style={{ display: "block" }}
        />
    );
        
        
    const popupIconNode = (
        <Icon
            icon="solar:chevron-down-linear"
            width={20}
            height={20}
            style={{ display: "block" }}
        />
    );
    
    return (
        <MuiAutocomplete
            options={options}
            value={value}
            inputValue={inputValue}
            onInputChange={(_, newInputValue) => setInputValue(newInputValue)}
            onChange={(_, newValue) => onChange?.(newValue)}
            getOptionLabel={(option) => {
                if (option === null) return '';
                return typeof option === 'string' ? option : option.label;
            }}
            sx={{
                ...(props.sx as any),
                width: '100%',
                
            }}
            renderInput={(params) => (
                <TextField
                    {...params}
                    label={label}
                    variant="filled"
                    placeholder={placeholder}
                    autoFocus={autoFocus}
                    error={error}
                    helperText={helperText}
                    sx={{
                        color: theme.palette.primary.main,
                        width: '100%',
                        border: '0.5px solid',
                        borderColor: alpha(theme.palette.primary.contrastText, 0.2),
                        borderRadius: 2,
                        backgroundColor: alpha(theme.palette.background.default, 0.6),
                        '&:focus-within': {
                            borderColor: alpha(theme.palette.primary.main, 0.8),
                        },
                        '& .MuiFilledInput-root': {
                            backgroundColor: 'transparent !important',
                            '&:before': { borderBottom: 'none' },
                            '&:after': { borderBottom: 'none' },
                            '&:hover': {
                                backgroundColor: 'transparent !important',
                                '&:before': { borderBottom: 'none' },
                            },
                            '&.Mui-focused': {
                                backgroundColor: 'transparent !important',
                            },
                            '&.Mui-disabled': {
                                backgroundColor: 'transparent !important',
                            },
                        },
                        '&:hover .MuiFilledInput-root': {
                            backgroundColor: 'transparent',
                            '&:before': { borderBottom: 'none' },
                            '&:after': { borderBottom: 'none' },
                            '&:hover:before': { borderBottom: 'none' },
                        },
                        '& .MuiInputLabel-root': {
                            color: alpha(theme.palette.primary.contrastText, 0.8),
                        },
                        '& .MuiInputLabel-root.Mui-focused': {
                            color: alpha(theme.palette.primary.contrastText, 0.8),
                        },
                        '& .MuiAutocomplete-clearIndicator': {
                            color: `${alpha(theme.palette.primary.contrastText, 0.8)} !important`,
                        },
                        '& .MuiAutocomplete-clearIndicator:hover': {
                            color: `${alpha(theme.palette.primary.contrastText, 0.6)} !important`,
                        },
                        '& .MuiAutocomplete-popupIndicator': {
                            color: `${alpha(theme.palette.primary.contrastText, 0.8)} !important`,
                        },
                        '& .MuiAutocomplete-popupIndicator:hover': {
                            color: `${alpha(theme.palette.primary.contrastText, 0.6)} !important`,
                        },
                    }}
                    slotProps={{
                        inputLabel: { required: false },
                    }}
                />
            )}
            {...props}
        />
    );
};

interface FormAutocompleteProps extends Omit<BaseAutocompleteProps, 'value' | 'onChange' | 'error' | 'helperText'> {
    name: string;
}

export const FormAutocomplete = ({
    name,
    options,
    label,
    placeholder,
    autoFocus,
    ...props
}: FormAutocompleteProps) => {
    const { control, formState: { errors } } = useFormContext();
    
    return (
        <Controller
            name={name}
            control={control}
            defaultValue=""
            render={({ field: { onChange, value, ...field } }) => {
                const error = errors[name];
                return (
                    <BaseAutocomplete
                        {...field}
                        {...props}
                        options={options}
                        label={label}
                        placeholder={placeholder}
                        autoFocus={autoFocus}
                        value={value}
                        onChange={onChange}
                        error={!!error}
                        helperText={error?.message as string}
                    />
                );
            }}
        />
    );
};

export default BaseAutocomplete;
