import { alpha, Box, Modal, Typography, useTheme } from "@mui/material";

interface BaseModalProps {
    open: boolean;
    onClose: () => void;
    title?: string;
    children?: React.ReactNode;
    actions?: React.ReactNode;
}

export default function BaseModal({ open, onClose, title, children, actions }: BaseModalProps) {
    const theme = useTheme();

    return (
        <Modal
            open={open}
            onClose={onClose}
            aria-labelledby="modal-title"
            aria-describedby="modal-description"
        >
            <Box sx={{
                position: 'absolute',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                width: '400px',
                bgcolor: 'background.paper',
                border: '1px solid',
                borderColor: alpha(theme.palette.primary.main, 0.2),
                borderRadius: 1,
                boxShadow: 24,
                p: 4,
            }}>
                {title && <Typography variant="h6" id="modal-title" sx={{ mb: 2 }}>
                    {title}
                </Typography>}
                {children && <Typography variant="body2" id="modal-description">
                    {children}
                </Typography>}
                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                    {actions}
                </Box>
            </Box>
        </Modal>
    );
}
