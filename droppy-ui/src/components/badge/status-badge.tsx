import { alpha, Box } from "@mui/material";


export default function StatusBadge({ text, color, ...props }: StatusBadgeProps) {
    
    return (
        <Box
        {...props}
        sx={{
            width: 'fit-content',
            color: color,
            fontWeight: 600,
            fontSize: '0.7rem',
            borderRadius: 1,
            paddingY: 0.25,
            paddingX: 0.5,
            backgroundColor: alpha(color, 0.2),
            ...props.sx,
        }}
        >
        {text}
        </Box>
    );
}

interface StatusBadgeProps {
    text: string;
    color: string;
}
  