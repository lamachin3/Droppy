import { Controller, useFormContext } from "react-hook-form";
import { alpha, Box, InputAdornment, TextField, useTheme, type TextFieldProps } from "@mui/material";


interface FormTextFieldProps extends Omit<TextFieldProps, 'name'> {
    name: string;
    formatIndicator?: React.ReactNode;
    endAdornment?: React.ReactNode;
}

export default function FormTextField({ name = '', sx, formatIndicator, endAdornment, ...props }: FormTextFieldProps) {
    const theme = useTheme();
    const { control } = useFormContext();

    
    const defaultSx = {
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
            '& .MuiFilledInput-input': {
                paddingRight: '8px', // Add some padding to prevent text from going under the adornment
            },
            '& .MuiInputAdornment-root': {
                marginLeft: 0,
                height: 'auto',
                '& .MuiBox-root': {
                    position: 'absolute',
                    right: '8px',
                    bottom: '8px',
                }
            }
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
    };
    
    return (
        <Controller
            name={name}
            control={control}
            defaultValue=""
            render={({ field, fieldState: { error } }) => (
                <TextField
                    {...field}
                    sx={[defaultSx, ...(Array.isArray(sx) ? sx : [sx])]}
                    variant="filled"
                    label={props.label}
                    error={!!error}
                    helperText={error?.message}
                    InputProps={{
                        endAdornment: (
                            <InputAdornment position="end">
                                {formatIndicator ? (
                                    <Box sx={{
                                        fontSize: '14px',
                                        color: alpha(theme.palette.primary.contrastText, 0.6),
                                        backgroundColor: theme.palette.background.default,
                                        borderRadius: 1,
                                        px: 1,
                                        py: 0.25,
                                    }}>
                                        {formatIndicator}
                                    </Box>
                                ) : (
                                    endAdornment
                                )}
                            </InputAdornment>
                        ),
                        ...props.InputProps,
                    }}
                    slotProps={{
                        inputLabel: { required: false },
                        ...props.slotProps,
                    }}
                    {...props}
                />
            )}
        />
    );
}
