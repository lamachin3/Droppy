import { Box, Card, CardHeader, CardActions, Typography, useTheme, alpha, Tooltip, IconButton, Grid } from '@mui/material';
import { Icon } from '@iconify/react';
import React from 'react';
import { useShimmer } from '@/hooks/use-shimmer';
import type { FileDataSummary } from '@/types';
import { DeleteModal } from '../modals/';
  
export default function FileListCard({ icon, file_data, onViewDetails, onDownload, onDelete }: FileListCardProps) {
    const theme = useTheme();
    const { shimmerStyles } = useShimmer();

    const [openDeleteModal, setOpenDeleteModal] = React.useState(false);
  
    return (
      <Card
        sx={{
          minWidth: "70%",
          color: "lightgray",
          borderRadius: 2.5,
          border: '1px solid',
          borderColor: alpha(theme.palette.grey[900], 1),
          backgroundColor: alpha(theme.palette.error.main, 0.1),
          transition: 'border-color 0.3s ease',
          ...shimmerStyles,
        }}
      >
        <Box display="flex" justifyContent="space-between" alignItems="center" width="100%">
        <CardHeader
          avatar={icon}
          title={
            <Grid container width="100%">
                <Grid size={12}>
                    <Typography variant="subtitle2" fontWeight="bold" color={theme.palette.primary.main}>
                        {file_data.filename}
                    </Typography>
                </Grid>
                <Grid size={12}>
                    <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        <Icon icon="solar:calendar-minimalistic-linear" width="14" height="14"/>
                        <span style={{ marginLeft: '0.3rem' }}>{file_data.created_at}</span>
                        <span style={{ marginLeft: '2rem' }}>{file_data.size}</span>
                    </Typography>
                </Grid>
            </Grid>
          }
        />
        <CardActions>
            <Typography variant="body2" color={theme.palette.primary.main} fontWeight="bold" sx={{ mr: 1 }}>
                [READY]
            </Typography>
        <Tooltip title="View file details" enterDelay={1000} leaveDelay={100}>
            <Box 
                sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    backgroundColor: alpha(theme.palette.primary.main, 0.1),
                    border: '1px solid', 
                    borderColor: alpha(theme.palette.primary.main, 0.2), 
                    borderRadius: 2,
                    '&:hover': {
                        backgroundColor: alpha(theme.palette.primary.main, 0.2),
                        borderColor: alpha(theme.palette.primary.main, 0.4),
                    },
                }}
            >
                <IconButton 
                    onClick={() => onViewDetails()} 
                    sx={{
                        backgroundColor: "transparent",
                        '&:hover': {
                            backgroundColor: "transparent",
                        },
                    }}>
                    <Icon icon="solar:eye-linear" width="16" height="16" color={theme.palette.primary.contrastText}/>
                </IconButton>
            </Box>
        </Tooltip>
        <Tooltip title="Download file" enterDelay={1000} leaveDelay={100}>
            <Box 
                sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    backgroundColor: alpha(theme.palette.primary.main, 0.1),
                    border: '1px solid', 
                    borderColor: alpha(theme.palette.primary.main, 0.2), 
                    borderRadius: 2,
                    '&:hover': {
                        backgroundColor: alpha(theme.palette.primary.main, 0.2),
                        borderColor: alpha(theme.palette.primary.main, 0.4),
                    },
                }}
            >
                <IconButton 
                    onClick={() => onDownload()} 
                    sx={{
                    backgroundColor: "transparent",
                    '&:hover': {
                        backgroundColor: "transparent",
                    },
                }}>
                    <Icon icon="solar:download-linear" width="16" height="16" color={theme.palette.primary.contrastText}/>
                </IconButton>
            </Box>
        </Tooltip>
        <Tooltip title="Delete file" enterDelay={1000} leaveDelay={100}>
            <Box 
                sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    backgroundColor: alpha(theme.palette.primary.main, 0.1),
                    border: '1px solid', 
                    borderColor: alpha(theme.palette.primary.main, 0.2), 
                    borderRadius: 2,
                    '&:hover': {
                        backgroundColor: alpha(theme.palette.primary.main, 0.2),
                        borderColor: alpha(theme.palette.primary.main, 0.4),
                    },
                }}
            >
                <IconButton
                    onClick={() => setOpenDeleteModal(true)} sx={{
                        backgroundColor: "transparent",
                        '&:hover': {
                            backgroundColor: "transparent",
                        },
                    }}
                >
                    <Icon icon="solar:trash-bin-trash-linear" width="16" height="16" color={theme.palette.error.main}/>
                </IconButton>
                <DeleteModal
                    open={openDeleteModal}
                    onClose={() => setOpenDeleteModal(false)}
                    handleDelete={() => onDelete()}
                    title="Delete file"
                    description="Are you sure you want to delete this file?"
                />
            </Box>
        </Tooltip>
        </CardActions>
        </Box>
      </Card>
    );
  }
  
  interface FileListCardProps {
    icon: React.ReactNode;
    file_data: FileDataSummary;
    onViewDetails: () => void;
    onDownload: () => void;
    onDelete: () => void;
  }