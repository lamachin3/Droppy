import { alpha, Button, useTheme, type ButtonProps } from "@mui/material";
import React from "react";


export default function CardButton({ children, ...props }: CardButtonProps) {
    const theme = useTheme();
    
    return (
        <Button
            variant="outlined"
            {...props}
            sx={{
                color: theme.palette.primary.contrastText,
                border: '0.5px solid',
                borderRadius: 1.5,
                borderColor: alpha(theme.palette.primary.main, 0.5),
                '&:hover': {
                backgroundColor: alpha(theme.palette.primary.main, 0.1),
                borderColor: alpha(theme.palette.primary.main, 0.8),
                },
                ...props.sx,
            }}
        >
            {children}
        </Button>
    );
}

interface CardButtonProps extends ButtonProps {
    children: React.ReactNode;
}
  