import { Chip, Grid, Link, List, ListItem, Typography, useTheme } from "@mui/material";

export function FileDetailsStrings({file}: {file: any}) {
    const theme = useTheme();

    const severityToColor = (severity: string) => {
        if (severity === 'low') return 'success';
        if (severity === 'medium') return 'warning';
        if (severity === 'high') return 'error';
        return 'info';
    };

    return (
        <Grid container spacing={2}>
            <Grid size={12}>
                <Typography variant="h6" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                    Extracted Strings
                </Typography>
                <Typography variant="body1" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                    {file.strings_results?.length} notable strings found in the binary
                </Typography>
                <List>
                    {file.strings_results?.map((str: {string: string, offsets: number[], caution_level: string, type: string}) => (
                        <ListItem key={str.string}>
                            <Grid container sx={{ width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                                <Grid size={6} sx={{ display: 'flex', alignItems: 'center' }}>
                                    <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600 }}>
                                        {str.string}
                                    </Typography>
                                    {str.caution_level !== null ? (
                                        <Chip 
                                            label={str.caution_level} 
                                            color={severityToColor(str.caution_level)} 
                                            size="small"
                                            variant="outlined" 
                                            sx={{ ml: 3, fontWeight: 800, height: "auto", fontSize: 12, textTransform: 'capitalize' }}
                                        />
                                    ) : null}
                                    <Chip
                                        label={str.type} 
                                        size="small" 
                                        variant="outlined" 
                                        sx={{ ml: 3, fontWeight: 800, height: "auto", fontSize: 12, textTransform: 'capitalize', color: theme.palette.primary.contrastText }}
                                    />
                                </Grid>
                                {str.type === 'API Function' ? (
                                    <Grid size={3} sx={{ display: 'flex', alignItems: 'center' }}>
                                        <Link href={`https://unprotect.it/featured-api/${str.string.toLowerCase()}/`} sx={{ ml: 5, display: 'flex', alignItems: 'center', gap: 1 }} target="_blank" rel="noreferrer">
                                            <img src="https://unprotect.it/static/img/favicon.ico" alt="" width="20" height="20" />
                                            <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 600 }}>
                                                Unprotect.it
                                            </Typography>
                                        </Link>
                                    </Grid>
                                ) : null}
                            </Grid>
                        </ListItem>
                    ))}
                </List>
            </Grid>
        </Grid>
    )
}