import { alpha, Box, Button, Modal, Typography, useTheme } from "@mui/material";
import { Icon } from "@iconify/react";

export default function DeleteModal({ open, onClose, handleDelete, title, description }: DeleteModalProps) {
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
                {description && <Typography variant="body2" id="modal-description">
                    {description}
                </Typography>}
                <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end', gap: 1 }}>
                    <Button
                        variant="outlined"
                        sx={{
                            backgroundColor: alpha(theme.palette.error.main, 0.15),
                            '&:hover': {
                                backgroundColor: alpha(theme.palette.error.main, 0.3),
                            },
                            color: theme.palette.error.main,
                        }}
                        onClick={handleDelete}
                        startIcon={<Icon icon="solar:trash-bin-trash-linear" width="16" height="16" color={theme.palette.error.main}/>}
                    >
                        Delete
                    </Button>
                    <Button variant="outlined" onClick={onClose}>
                        Cancel
                    </Button>
                </Box>
            </Box>
        </Modal>
    );
}
        
interface DeleteModalProps {
    open: boolean;
    onClose: () => void;
    handleDelete: () => void;
    title?: string;
    description?: string;
}
