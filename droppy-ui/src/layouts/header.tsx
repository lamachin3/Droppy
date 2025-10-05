import { Container, Toolbar, Typography, Box, useTheme, IconButton, Menu, MenuItem, alpha } from '@mui/material';
import { GlassAppBar, PulsingDot } from '@/components';
import { Icon } from '@iconify/react';
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { logout, getCurrentUser } from '@/services/api';

export default function Header() {
    const theme = useTheme();
    const navigate = useNavigate();

    const user = localStorage.getItem("user_data") ? JSON.parse(localStorage.getItem("user_data") as string) : getCurrentUser();

    const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null);
    const open = Boolean(anchorEl);

    const handleClick = (event: React.MouseEvent<HTMLElement>) => {
        setAnchorEl(event.currentTarget);
    };
    const handleClose = () => {
        setAnchorEl(null);
    };

    const handleLogout = async () => {
        await logout();
        navigate('/login');
    };

    return (
        <GlassAppBar>
            <Container maxWidth={false}>
                <Toolbar disableGutters sx={{ gap: 2, marginLeft: '3rem', marginRight: '1rem' }}>
                    <Box sx={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 3 }} onClick={() => navigate('/')}>
                        <Icon
                            icon="streamline-pixel:design-dropper-1"
                            width={32}
                            height={32}
                            color={theme.palette.secondary.main}
                        />

                        <Box
                            sx={{ display: 'flex', flexDirection: 'column', justifyContent: 'center' }}
                        >
                            <Typography
                            sx={{
                                fontSize: '1.5rem',
                                fontWeight: 900,
                                color: theme.palette.primary.contrastText,
                                lineHeight: 1,
                            }}
                            >
                            DROPPY
                            </Typography>
                            <Typography
                            variant="body1"
                            sx={{
                                fontSize: '0.8rem',
                                fontWeight: 'bold',
                                color: theme.palette.secondary.main,
                                lineHeight: 1,
                            }}
                            >
                            MALWARE TOOLING UTILITY
                            </Typography>
                        </Box>
                    </Box>

                    <Box sx={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            <PulsingDot color={theme.palette.secondary.main} />
                            <Typography variant="body2" sx={{ fontWeight: 600, color: theme.palette.secondary.main }}>
                            READY
                            </Typography>
                        </Box>
                        
                        <Box 
                            onClick={handleClick}
                            sx={{ 
                                display: 'flex',
                                alignItems: 'center',
                                gap: 1,
                                pr: 1.5,
                                cursor: 'pointer',
                                borderRadius: 2,
                                border: '1px solid',
                                borderColor: alpha(theme.palette.primary.main, 0.2),
                                backgroundColor: alpha(theme.palette.primary.main, 0.1),
                                transition: 'border-color 0.3s ease',
                                '&:hover': {
                                    borderColor: alpha(theme.palette.primary.main, 0.4),
                                },
                            }}
                        >
                            <IconButton>
                                <Icon icon="solar:user-bold" width={24} height={24} color={theme.palette.primary.main}/>
                            </IconButton>
                            <Typography 
                                variant="body2" 
                                sx={{ 
                                    fontWeight: 600, 
                                    color: theme.palette.text.primary,
                                    fontFamily: theme.typography.fontFamily,
                                }}
                            >
                                {user?.firstname || user?.email.split("@")[0]}
                            </Typography>
                        </Box>
                        <Menu
                            anchorEl={anchorEl}
                            open={open}
                            onClose={handleClose}
                            slotProps={{
                                list: {
                                    sx: {
                                        backgroundColor: theme.palette.background.paper,
                                        border: '1px solid',
                                        borderColor: theme.palette.divider,
                                        borderRadius: 2,
                                        minWidth: 120,
                                    },
                                }
                            }}
                        >
                            <MenuItem 
                                onClick={handleLogout}
                                sx={{
                                    color: theme.palette.text.primary,
                                    fontFamily: theme.typography.fontFamily,
                                    '&:hover': {
                                        backgroundColor: alpha(theme.palette.primary.main, 0.2),
                                    },
                                }}
                            >
                                <Icon icon="solar:logout-2-linear" style={{ marginRight: 8 }} />
                                Logout
                            </MenuItem>
                        </Menu>
                    </Box>
                </Toolbar>
            </Container>
        </GlassAppBar>
    );
}
