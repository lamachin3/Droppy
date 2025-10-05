import { Icon } from "@iconify/react";
import { Grid, Typography, useTheme } from "@mui/material";
import { CardButton } from "@/components";

export function FileDetailsVirustotal({file}: {file: any}) {
    const theme = useTheme();

    return (
        <Grid container spacing={2} rowGap={3}>
            <Grid size={1} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon icon="simple-icons:virustotal" width="40" height="40" />
            </Grid>
            <Grid size={8}>
                <Typography variant="h6" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                    Virustotal
                </Typography>
                <Typography variant="body1" color={theme.palette.grey[600]} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                    Multi-engine antivirus scan results
                </Typography>
            </Grid>
            <Grid size={3} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
                <CardButton 
                    sx={{ ml: 5, color: theme.palette.primary.main }} 
                    href={file.virustotal_results.scan_data?.permalink} 
                    target="_blank"
                    rel="noreferrer"
                    startIcon={<Icon icon="solar:eye-linear" width="20" height="20" />}
                >
                    Open VirusTotal
                </CardButton>
            </Grid>
            {file.virustotal_results?.found ? (
                <>
                <Grid size={6}>
                    <Typography variant="body1" color={theme.palette.grey[600]} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        Detection ratio
                    </Typography>
                    <Typography
                        color={theme.palette.primary.main}
                        sx={{ fontWeight: 800, fontSize: 22, display: 'flex', alignItems: 'center' }}>
                        {file.virustotal_results.scan_data.detection_ratio}
                    </Typography>
                </Grid>
                <Grid size={6}>
                    <Typography variant="body1" color={theme.palette.grey[600]} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        Community score
                    </Typography>
                    <Typography
                        color={theme.palette.primary.main}
                        sx={{ fontWeight: 800, fontSize: 22, display: 'flex', alignItems: 'center' }}>
                        {file.virustotal_results.scan_data.community_score}
                    </Typography>
                </Grid>
                <Grid size={6}>
                    <Typography variant="body1" color={theme.palette.grey[600]} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        First scan date
                    </Typography>
                    <Typography variant="body1" color={theme.palette.primary.main} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        {new Date(file.virustotal_results.scan_data.first_submission_date).toLocaleString()}
                    </Typography>
                </Grid>
                <Grid size={6}>
                    <Typography variant="body1" color={theme.palette.grey[600]} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        Last scan date
                    </Typography>
                    <Typography variant="body1" color={theme.palette.primary.main} sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                        {new Date(file.virustotal_results.scan_data.last_submission_date).toLocaleString()}
                    </Typography>
                </Grid>
                </>
            ) : (
                <Grid size={12} sx={{ mt: 2, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    <Typography variant="body1" color={theme.palette.primary.main} sx={{ fontWeight: 600, fontSize: 22, display: 'flex', alignItems: 'center' }}>
                        <Icon icon="solar:eye-scan-linear" width="36" height="36" style={{ marginRight: "1rem" }} />
                        No scan results available
                    </Typography>
                </Grid>
            )}
        </Grid>
    )
}