import { alpha, Button, useTheme, type ButtonProps } from "@mui/material";
import React from "react";


export default function SubmitButton({ children, ...props }: SubmitButtonProps) {
    const theme = useTheme();
    
    return (
        <Button
            variant="outlined"
            type="submit"
            {...props}
            sx={{
                color: alpha(theme.palette.primary.contrastText, 0.9),
                borderRadius: 1.5,
                border: 'none',
                backgroundColor: alpha(theme.palette.primary.main, 0.75),
                '&:hover': {
                    boxShadow: `0 0 10px 10px ${alpha(theme.palette.primary.main, 0.15)}`,
                },  
                ...props.sx,
            }}
        >
            {children}
        </Button>
    );
}

interface SubmitButtonProps extends ButtonProps {
    children: React.ReactNode;
}
  