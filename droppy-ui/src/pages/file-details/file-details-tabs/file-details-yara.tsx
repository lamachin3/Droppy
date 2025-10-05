import { Icon } from "@iconify/react";
import { Box, Chip, Grid, Typography, useTheme, Accordion, AccordionSummary, AccordionDetails, Link, List, ListItem, alpha } from "@mui/material";
import { CardButton, PanelCard } from "@/components";
import { useState } from "react";

export function FileDetailsYara({file}: {file: any}) {
    const theme = useTheme();

    const severityToLabel = (s: number) => {
        if (s < 40) return 'low';
        if (s < 60) return 'noteworthy';
        if (s < 80) return 'suspicious';
        return 'high';
    };

    const severityToColor = (s: number) => {
        if (s < 40) return 'success';
        if (s < 60) return 'info';
        if (s < 80) return 'warning';
        return 'error';
    };

    return (
        <Grid container spacing={2}>
            <Grid size={1} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Icon icon="file-icons:yara" width="40" height="40" />
            </Grid>
            <Grid size={11}>
                <Typography variant="h6" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center' }}>
                    Yara Results
                </Typography>
                <Typography variant="body1" color="grey" sx={{ fontWeight: 600, display: 'flex', alignItems: 'center' }}>
                    {file.yara_results?.length} rule{file.yara_results?.length > 1 ? 's were' : ' was'} triggered
                </Typography>
            </Grid>
            {file.yara_results?.map((yara: any) => {
                const [expanded, setExpanded] = useState(false);

                const handleToggle = (event: React.MouseEvent) => {
                    event.stopPropagation();
                    const summary = event.currentTarget.closest('.MuiAccordion-root')?.querySelector('.MuiAccordionSummary-root');
                    summary?.click();
                    setExpanded(!expanded);
                };

                return (
                    <PanelCard icon="" sx={{ width: '100%', p: 0 }}>
                        <Accordion sx={{ width: '100%', height: '100%', background: 'transparent' }}>
                            <AccordionSummary
                                sx={{
                                    color: theme.palette.primary.main,
                                    pointerEvents: "none",
                                    m: 0,
                                    px: 0, // remove default horizontal padding
                                    minHeight: "auto", // remove default tall min-height
                                    "& .MuiAccordionSummary-content": {
                                      m: 0, // remove default margin
                                      width: "100%", // force content to respect accordion width
                                      minWidth: 0,   // IMPORTANT: allows flex children to shrink
                                    },
                                }}
                                expandIcon={null}
                                aria-controls="panel1-content"
                                id="panel1-header"
                            >
                                <Grid container sx={{ width: '100%' }} alignItems="center">
                                    <Grid size={9}>
                                        <Grid container>
                                            <Grid size={12} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                                <Typography variant="body2" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, display: 'flex', alignItems: 'center', mr: 2 }}>
                                                    {yara.rule}
                                                </Typography>
                                                <Chip
                                                    label={severityToLabel(yara.meta.severity)}
                                                    color={severityToColor(yara.meta.severity)}
                                                    variant="filled"
                                                    size="small"
                                                    sx={{ fontWeight: 800, height: "auto", fontSize: 12, color: theme.palette.primary.contrastText, textTransform: 'capitalize' }}
                                                />
                                                <Chip
                                                    label={`${yara.meta.severity}%`}
                                                    variant="outlined"
                                                    size="small"
                                                    sx={{ fontWeight: 800, height: "auto", fontSize: 12, color: theme.palette.primary.contrastText, textTransform: 'capitalize', px: 0.3 }}
                                                />
                                            </Grid>
                                            <Grid size={12} sx={{ overflow: expanded ? "visible" : "hidden", textOverflow: expanded ? "visible" : "ellipsis", whiteSpace: expanded ? "visible" : "nowrap" }}>
                                                <Typography
                                                    variant="body1"
                                                    color={theme.palette.grey[600]}
                                                    noWrap={!expanded}
                                                    sx={{ fontWeight: 600 }}
                                                >
                                                    {yara.meta.description}
                                                </Typography>
                                            </Grid>
                                        </Grid>
                                    </Grid>
                                    <Grid size={3} sx={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end' }}>
                                        <CardButton 
                                            sx={{ color: theme.palette.primary.main, pointer: "cursor", pointerEvents: "auto" }}
                                            onClick={handleToggle}
                                            endIcon={expanded ? <Icon icon="solar:alt-arrow-up-line-duotone" width="20" height="20" /> : <Icon icon="solar:alt-arrow-down-line-duotone" width="20" height="20" />}
                                        >
                                            {expanded ? "Hide Details" : "View Details"}
                                        </CardButton>
                                    </Grid>
                                </Grid>
                            </AccordionSummary>
                            <AccordionDetails>
                                <Grid container rowSpacing={2}>
                                    {yara.meta.author && (
                                        <Grid size={4}>
                                            <Typography variant="caption" color={theme.palette.grey[500]}>Author</Typography>
                                            <Typography variant="body2" color={theme.palette.primary.contrastText}>{yara.meta.author}</Typography>
                                        </Grid>
                                    )}
                                    {(yara.meta.last_modified || yara.meta.creation_date) && (
                                        <Grid size={4}>
                                            <Typography variant="caption" color={theme.palette.grey[500]}>Date</Typography>
                                            <Typography variant="body2" color={theme.palette.primary.contrastText}>{yara.meta.last_modified || yara.meta.creation_date}</Typography>
                                        </Grid>
                                    )}
                                    {yara.meta.os && (
                                        <Grid size={4}>
                                            <Typography variant="caption" color={theme.palette.grey[500]}>OS</Typography>
                                            <Typography variant="body2" color={theme.palette.primary.contrastText}>{yara.meta.os}</Typography>
                                        </Grid>
                                    )}

                                    {yara.meta.reference && (
                                        <Grid size={12}>
                                            <Typography variant="caption" color={theme.palette.grey[500]}>Reference</Typography>
                                            <Link href={yara.meta.reference} target="_blank">
                                                <Typography variant="body2" color={theme.palette.primary.contrastText}>{yara.meta.reference}</Typography>
                                            </Link>
                                        </Grid>
                                    )}

                                    {yara.strings && (
                                        <Grid size={12}>
                                            <Typography variant="caption" color={theme.palette.grey[500]}>Matches found</Typography>
                                            <List sx={{ '& > * + *': { mt: 1 } }}>
                                                {yara.strings.map((s: string) => (
                                                    <ListItem
                                                        key={s.identifier}
                                                        sx={{ 
                                                            borderLeft: `2px solid ${theme.palette.error.main}`,
                                                            borderRadius: '0 4px 4px 0',
                                                            backgroundColor: alpha(theme.palette.error.main, 0.05),
                                                            display: 'flex',
                                                            justifyContent: 'space-between',
                                                            alignItems: 'center',
                                                            gap: 2,
                                                            pr: 1
                                                        }}
                                                    >
                                                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                                                            <Typography variant="body2" color={theme.palette.primary.contrastText} fontSize={13}>0x{s.offset}</Typography>
                                                            <Typography variant="body2" color={theme.palette.primary.contrastText} fontWeight={600}>
                                                                {s.data}
                                                            </Typography>
                                                        </Box>
                                                        <Chip 
                                                            label={s.identifier} 
                                                            color="primary" 
                                                            variant="outlined" 
                                                            size="small" 
                                                            sx={{ 
                                                                px: 0.5,
                                                                ml: 'auto',
                                                                flexShrink: 0
                                                            }} 
                                                        />
                                                    </ListItem>
                                                ))}
                                            </List>
                                        </Grid>
                                    )}
                                </Grid>
                            </AccordionDetails>
                        </Accordion>
                    </PanelCard>
                )}
            )}
        </Grid>
    )
}