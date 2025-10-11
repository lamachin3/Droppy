import { useEffect, useState } from 'react';
import { useNavigate, useParams } from "react-router-dom";
import { Backdrop, Button, Grid, Toolbar, Typography, alpha, Box, Divider, CircularProgress, Alert, IconButton, Switch, Snackbar, TextField } from "@mui/material";
import { useTheme } from "@mui/material/styles";
import { FileDetailsLayout } from "@/layouts/file-details";
import { Icon } from "@iconify/react";
import { FileDetailsTabs } from "./file-details-tabs";
import { getBuild, deleteBuild, downloadBuild, type Build } from "@/services/api/buildsServices";
import { BaseModal, DeleteModal, PanelCard } from '@/components';
import { toggleTemplateState, renameTemplate, downloadTemplate } from '@/services/api/configTemplatesService';


export default function FileDetails() {
    const theme = useTheme();
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState('');
    const { id } = useParams<{ id: string }>();
    const [file, setFile] = useState<Build | null>(null);
    const [isLoading, setIsLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [openDeleteModal, setOpenDeleteModal] = useState(false);
    const [openTemplateNameModal, setOpenTemplateNameModal] = useState(false);
    const [templateName, setTemplateName] = useState('');
    const [openErrorSnackbar, setOpenErrorSnackbar] = useState(false);
    const [isToggling, setIsToggling] = useState(false);

    useEffect(() => {
        const fetchFileDetails = async () => {
            if (!id) {
                navigate('/');
                return;
            }

            try {
                setIsLoading(true);
                const build = await getBuild(id);
                
                setFile(build);
                setTemplateName(build.config.name);
            } catch (err) {
                navigate('/');
            } finally {
                setIsLoading(false);
            }
        };

        if (!file) {
            fetchFileDetails();
        }
    }, [id, navigate, file]);

    const handleTabChange = (tabId: string) => {
        setActiveTab(tabId);
    };

    const handleDeleteBuild = async () => {
        try {
            await deleteBuild(id);
            navigate('/');
        } catch (err) {
            setError('Failed to delete build. Please try again.');
            setOpenErrorSnackbar(true);
        }
    };

    const handleTemplateToggle = async () => {   
        const previousState = file.config.is_template;
        const newState = !previousState;
      
        setFile({ ...file, config: { ...file.config, is_template: newState } });
        setIsToggling(true);
      
        try {
            await toggleTemplateState(file.config.id);
        } catch (err) {
            setError("Failed to toggle template. Please try again.");
            setOpenErrorSnackbar(true);
            setFile({ ...file, config: { ...file.config, is_template: previousState } });
        } finally {
            setIsToggling(false);
        }
    };

    const handleTemplateNameSubmit = async () => {
        try {
            await renameTemplate(file.config.id, templateName);
            setFile({ ...file, config: { ...file.config, name: templateName } });
        } catch (err) {
            setError("Failed to rename template. Please try again.");
            setOpenErrorSnackbar(true);
        }
        setOpenTemplateNameModal(false);
    };

    if (isLoading) {
        return (
            <Backdrop
                sx={{ color: '#fff', zIndex: (theme) => theme.zIndex.drawer + 1 }}
                open
            >
                <CircularProgress color="primary" />
            </Backdrop>
        );
    }

    return (
        <FileDetailsLayout>
            <Button 
                variant="text" 
                sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1, color: theme.palette.primary.contrastText, "&:hover": { color: theme.palette.primary.main, backgroundColor: "transparent" } }} 
                onClick={() => navigate('/')}
            >
                <Icon icon="ph:arrow-left" width="20" height="20" /> Back to Home
            </Button>

            <Grid container>
                <Grid size={9}>
                    <Toolbar disableGutters sx={{ gap: 2, mb: "1.5rem" }}>
                        {file.filename.split(".").pop() === "exe" || file.filename.split(".").pop() === "dll" ? (
                            <Icon icon="devicon:windows11" width="40" height="40" />
                        ) : (
                            <Icon icon="solar:code-file-linear" width="40" height="40" />
                        )}
                        <div>
                            <Typography variant="h5" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, fontSize: "1.8rem" }}>
                                {file.filename}
                            </Typography>
                            <Typography variant="body1" color={alpha(theme.palette.primary.contrastText, 0.7)} sx={{ fontWeight: 500 }}>
                                {file.type} • {file.architecture}
                            </Typography>
                        </div>
                    </Toolbar>
                </Grid>
                <Grid size={3} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mr: 4 }}>
                        <Switch 
                            checked={file.config.is_template}
                            onChange={handleTemplateToggle}
                            disabled={isToggling}
                        />
                        {/* Make the 2 typography one above the other */}
                        <Box sx={{ display: 'flex', flexDirection: 'column' }}>
                            <Typography variant="body1" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: "0.9rem", textTransform: 'uppercase', lineHeight: 1 }}>
                                Template
                            </Typography>
                        </Box>
                    </Box>
                    <IconButton
                        onClick={() => downloadBuild(id)}
                        sx={{
                            mr: 2,
                            height: "auto",
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                            borderRadius: 2,
                            border: '1px solid',
                            borderColor: alpha(theme.palette.error.contrastText, 0.2),
                            backgroundColor: alpha(theme.palette.error.contrastText, 0.1),
                            '&:hover': {
                                backgroundColor: alpha(theme.palette.error.contrastText, 0.2),
                            },
                        }}
                    >
                        <Icon icon="solar:download-linear" width="22" height="22" color={theme.palette.error.contrastText}/>
                        <Typography variant="body2" color={theme.palette.error.contrastText} sx={{ fontWeight: 600 }}>
                            Download
                        </Typography>
                    </IconButton>
                    <IconButton
                        onClick={() => setOpenDeleteModal(true)}
                        sx={{
                            height: "auto",
                            display: 'flex',
                            alignItems: 'center',
                            gap: 1,
                            borderRadius: 2,
                            border: '1px solid',
                            borderColor: alpha(theme.palette.error.main, 0.2),
                            backgroundColor: alpha(theme.palette.error.main, 0.1),
                            '&:hover': {
                                backgroundColor: alpha(theme.palette.error.main, 0.2),
                            },
                        }}
                    >
                        <Icon icon="solar:trash-bin-trash-linear" width="22" height="22" color={theme.palette.error.main}/>
                        <Typography variant="body2" color={theme.palette.error.main} sx={{ fontWeight: 600 }}>
                            Delete
                        </Typography>
                    </IconButton>
                    <DeleteModal
                        open={openDeleteModal}
                        onClose={() => setOpenDeleteModal(false)}
                        handleDelete={handleDeleteBuild}
                        title="Delete file"
                        description="Are you sure you want to delete this file?"
                    />
                </Grid>
            </Grid>
            
            <Grid container spacing={3}>
                {file?.config.is_template && (
                    <Grid size={12}>
                        <PanelCard
                            icon={<Icon icon="solar:code-file-linear" width="22" height="22" />}
                            title="Template"
                            sx={{ width: '100%', color: theme.palette.primary.contrastText }}
                        >
                            <Grid container>
                                <Grid size={4}>
                                    <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                                        Template Name
                                    </Typography>
                                    <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                                        {file?.config.name}
                                    </Typography>
                                </Grid>
                                <Grid size={4}>
                                    <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                                        Template Type
                                    </Typography>
                                    <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                                        {file?.config.dropper_type}
                                    </Typography>
                                </Grid>
                                <Grid size={4} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 3 }}>
                                    <IconButton
                                        onClick={() => setOpenTemplateNameModal(true)}
                                        sx={{
                                            height: "auto",
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: 1,
                                            borderRadius: 2,
                                            border: '1px solid',
                                            borderColor: alpha(theme.palette.primary.contrastText, 0.2),
                                            backgroundColor: alpha(theme.palette.primary.contrastText, 0.1),
                                            '&:hover': {
                                                backgroundColor: alpha(theme.palette.primary.contrastText, 0.2),
                                            },
                                        }}
                                    >
                                        <Icon icon="solar:pen-new-square-linear" width="22" height="22" color={theme.palette.primary.contrastText}/>
                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600 }}>
                                            Rename
                                        </Typography>
                                    </IconButton>

                                    <IconButton
                                        onClick={() => downloadTemplate(file.config.id)}
                                        sx={{
                                            height: "auto",
                                            display: 'flex',
                                            alignItems: 'center',
                                            gap: 1,
                                            borderRadius: 2,
                                            border: '1px solid',
                                            borderColor: alpha(theme.palette.primary.main, 0.2),
                                            backgroundColor: alpha(theme.palette.primary.main, 0.1),
                                            '&:hover': {
                                                backgroundColor: alpha(theme.palette.primary.main, 0.2),
                                            },
                                        }}
                                    >
                                        <Icon icon="solar:download-linear" width="22" height="22" color={theme.palette.primary.contrastText}/>
                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600 }}>
                                            Download JSON
                                        </Typography>
                                    </IconButton>
                                </Grid>
                            </Grid>
                        </PanelCard>
                    </Grid>
                )}
                <Grid size={12}>
                    <PanelCard
                        icon={<Icon icon="solar:file-text-linear" width="22" height="22" />}
                        title="File Overview"
                        sx={{ width: '100%', color: theme.palette.primary.contrastText }}
                    >
                        <Grid container>
                            <Grid size={4}>
                                <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                                    Created At
                                </Typography>
                                <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                                    { new Date(file.created_at).toLocaleString() }
                                </Typography>
                            </Grid>
                            <Grid size={4}>
                                <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                                    Builder Type
                                </Typography>
                                <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                                    {file.config.dropper_type || "-"}
                                </Typography>
                            </Grid>
                            <Grid size={4}>
                                <Typography variant="body2" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                                    Size
                                </Typography>
                                <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                                    {file.size}
                                </Typography>
                            </Grid>
                        </Grid>
                    </PanelCard>
                    <PanelCard
                        icon={<Icon icon="solar:hashtag-bold" width="22" height="22" />}
                        title="Hashes"
                        sx={{ width: '100%', color: theme.palette.primary.contrastText, mt: 2 }}
                    >
                        <Grid container>
                            <Grid size={12}>
                                <Grid container>
                                    <Grid size={2}>
                                        <Typography variant="body2" color="grey" sx={{ fontWeight: 600 }}>
                                            MD5:
                                        </Typography>
                                    </Grid>
                                    <Grid size={10}>
                                        <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800 }}>
                                            {file.md5_hash}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            <Grid size={12}>
                                <Grid container>
                                    <Grid size={2}>
                                        <Typography variant="body2" color="grey" sx={{ fontWeight: 600 }}>
                                            SHA1:
                                        </Typography>
                                    </Grid>
                                    <Grid size={10}>
                                        <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800 }}>
                                            {file.sha1_hash}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                            <Grid size={12}>
                                <Grid container>
                                    <Grid size={2}>
                                        <Typography variant="body2" color="grey" sx={{ fontWeight: 600 }}>
                                            SHA256:
                                        </Typography>
                                    </Grid>
                                    <Grid size={10}>
                                        <Typography color={theme.palette.primary.contrastText} sx={{ fontWeight: 800 }}>
                                            {file.sha256_hash}
                                        </Typography>
                                    </Grid>
                                </Grid>
                            </Grid>
                        </Grid>
                    </PanelCard>
                    <PanelCard
                        icon={<Icon icon="ph:wrench-fill" width="22" height="22" />}
                        title="Build Configuration"
                        subheader="Modules and options used for compilation"
                        sx={{ mt: 2 }}
                    >
                        <Grid container>
                            <Grid size={12}>
                                <Grid container>
                                    <Grid size={12}>
                                        <Typography variant="body1" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, fontSize: '18px' }}>
                                            Evasion Modules
                                        </Typography>
                                    </Grid>
                                    <Grid size={12} sx={{ mb: 2 }}>
                                        <Grid container rowSpacing={1} spacing={{ xs: 2, md: 3 }} sx={{ mt: 0.5 }}>
                                            {Object.keys(file.config.features).map((module) => file.config.features[module] && (
                                                <Grid size={4} key={module}>
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:check-circle" width="18" height="18" color={theme.palette.primary.main} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            {file.config.features[module]}
                                                        </Typography>
                                                    </Box>
                                                </Grid>
                                            ))}
                                        </Grid>
                                    </Grid>
                                </Grid>
                                <Divider sx={{ mt: 1, mb: 2 }} />
                                <Grid container>
                                    <Grid size={12}>
                                        <Typography variant="body1" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, fontSize: '18px' }}>
                                            Options
                                        </Typography>
                                    </Grid>
                                    <Grid size={12}>
                                        <Grid container rowSpacing={2} spacing={{ xs: 2, md: 3 }} sx={{ mt: 1 }}>
                                            <Grid size={4}>
                                                <Typography variant="body2" color={theme.palette.grey[600]} sx={{ fontWeight: 600, fontSize: '15px' }}>
                                                    Debug Mode
                                                </Typography>
                                                {file.config.options.debug_mode ? (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:check-circle" width="18" height="18" color={theme.palette.primary.main} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Enabled
                                                        </Typography>
                                                    </Box>
                                                ) : (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:times-circle" width="18" height="18" color={theme.palette.grey[500]} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Disabled
                                                        </Typography>
                                                    </Box>
                                                )}
                                            </Grid>
                                            <Grid size={4}>
                                                <Typography variant="body2" color={theme.palette.grey[600]} sx={{ fontWeight: 600, fontSize: '15px' }}>
                                                    Hide Console
                                                </Typography>
                                                {file.config.options.hide_console ? (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:check-circle" width="18" height="18" color={theme.palette.primary.main} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Enabled
                                                        </Typography>
                                                    </Box>
                                                ) : (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:times-circle" width="18" height="18" color={theme.palette.grey[500]} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Disabled
                                                        </Typography>
                                                    </Box>
                                                )}
                                            </Grid>
                                            <Grid size={4}>
                                                <Typography variant="body2" color={theme.palette.grey[600]} sx={{ fontWeight: 600, fontSize: '15px' }}>
                                                    Output Redirection
                                                </Typography>
                                                {file.config.options.redirect_output ? (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:check-circle" width="18" height="18" color={theme.palette.primary.main} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Enabled
                                                        </Typography>
                                                    </Box>
                                                ) : (
                                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                        <Icon icon="prime:times-circle" width="18" height="18" color={theme.palette.grey[500]} />
                                                        <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                            Disabled
                                                        </Typography>
                                                    </Box>
                                                )}
                                            </Grid>
                                            {file.config.options.remote_process_name && (
                                                <Grid size={4}>
                                                    <Typography variant="body2" color={theme.palette.grey[600]} sx={{ fontWeight: 600, fontSize: '15px' }}>
                                                        Remote Process
                                                    </Typography>
                                                    <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600, fontSize: '16px' }}>
                                                        {file.config.options.remote_process_name}
                                                    </Typography>
                                                </Grid>
                                            )}
                                        </Grid>
                                    </Grid>
                                </Grid>
                            </Grid>
                        </Grid>
                    </PanelCard>
                    <PanelCard
                        icon={null}
                        sx={{ mt: 2 }}
                    >
                        <FileDetailsTabs activeTab={activeTab} handleTabChange={handleTabChange} file={file} />
                    </PanelCard>
                </Grid>
            </Grid>
            {error && (
                <Snackbar 
                    open={openErrorSnackbar} 
                    autoHideDuration={5000}
                    onClose={() => setOpenErrorSnackbar(false)}
                >
                    <Alert severity="error" sx={{ width: '100%' }}>
                        {error}
                    </Alert>
                </Snackbar>
            )}
            {openTemplateNameModal && (
                <BaseModal
                    open={openTemplateNameModal}
                    onClose={() => setOpenTemplateNameModal(false)}
                    title="Template Name"
                    actions={
                        <>
                            <Button variant="outlined" onClick={() => setOpenTemplateNameModal(false)}>
                                Cancel
                            </Button>
                            <Button variant="contained" onClick={() => handleTemplateNameSubmit()}>
                                Save
                            </Button>
                        </>
                    }
                >
                    <TextField
                        variant="outlined"
                        label=""
                        value={templateName}
                        onChange={(e) => setTemplateName(e.target.value)}
                        fullWidth
                        sx={{ mb: 2 }}
                    />
                </BaseModal>
            )}
        </FileDetailsLayout>
    )
}