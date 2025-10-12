import { Box, Toolbar, Typography, CircularProgress, Alert, Grid, alpha, Snackbar } from '@mui/material';
import { Icon } from '@iconify/react';
import { ModuleCard, FileListCard } from '@/components';
import { useTheme } from '@mui/material';
import { ROUTES } from '@/routes';
import { useNavigate } from 'react-router-dom';
import { HomeLayout } from '@/layouts/home';
import { useEffect, useState } from 'react';
import { listBuilds, downloadBuild, formatFileSize, deleteBuild, type Build } from '@/services/api/buildsServices';


export default function Home() {
  const theme = useTheme();
  const navigate = useNavigate();
  const [builds, setBuilds] = useState<Build[]>([]);
  const [loading, setLoading] = useState(false);
  
  const [openAlert, setOpenAlert] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    const fetchBuilds = async () => {
      try {
        setLoading(true);
        const response = await listBuilds();
        setBuilds(response.results);
      } catch (err) {
        console.error('Failed to fetch builds:', err);
        setError('Failed to load builds. Please try again later.');
        setOpenAlert(true);
      } finally {
        setLoading(false);
      }
    };

    fetchBuilds();
  }, []);

  const handleDeleteBuild = async (buildId: string) => {
    try {
      await deleteBuild(buildId);
      setBuilds(builds.filter(build => build.id !== buildId));
      setMessage('Build deleted successfully.');
    } catch (err) {
      console.error('Failed to delete build:', err);
      setError('Failed to delete build. Please try again.');
    }
    setOpenAlert(true);
  };

  return (
    <HomeLayout>
      <Toolbar disableGutters sx={{ gap: 0, my: "1rem" }}>
        <Icon icon="ph:wrench-duotone" width="32" height="32" color={theme.palette.error.main} style={{ marginRight: '1rem' }} />
        <div>
          <Typography variant="h6" color="lightgray" sx={{ fontWeight: 800, mb: -0.8 }} >
            Builder Modules
          </Typography>
          <Typography variant="body2" color="lightgray" >
            4 modules available
          </Typography>
        </div>
      </Toolbar>
      <Grid container spacing={2}>
        <Grid size={{ xs: 6, md: 4 }}>
          <ModuleCard
            icon={<Icon icon="solar:magic-stick-3-linear" width={28} height={28} color={theme.palette.primary.main} />}
            title="Basic dropper"
            status="new"
            content="Easy to use dropper builder with predefined evasion techniques"
            buttonText="Access module"
            onAction={() => navigate(ROUTES.BASIC_DROPPER)}
          />
        </Grid>
        <Grid size={{ xs: 6, md: 4 }}>
        <ModuleCard
          icon={<Icon icon="solar:mask-happly-linear" width={28} height={28} color={theme.palette.primary.main} />}
          title="Advanced dropper"
          status="new"
          content="Build your dropper with more control over the evasion techniques implemented"
          buttonText="Access module"
          onAction={() => navigate(ROUTES.ADVANCED_DROPPER)}
            />
        </Grid>
        <Grid size={{ xs: 6, md: 4 }}>
          <ModuleCard 
            icon={<Icon icon="solar:code-file-linear" width={28} height={28} color={theme.palette.primary.main} />}
            title="Templates"
            status="upcoming"
            content="Manage your templates and use for them to build droppers"
            buttonText="Access module"
            onAction={() => console.log("click")}
          />
        </Grid>
        <Grid size={{ xs: 6, md: 4 }}>
          <ModuleCard 
            icon={<Icon icon="solar:link-linear" width={28} height={28} color={theme.palette.primary.main} />}
            title="Kill chain builder"
            status="upcoming"
            content="Advanced multi-stage attack chain builder with APT-style techniques"
            buttonText="Access module"
            onAction={() => console.log("click")}
          />
        </Grid>
        {/*<Grid size={{ xs: 6, md: 4 }}>
          <ModuleCard
          icon={<img src="src/assets/icons/cobalt-strike.png" alt="Cobalt Strike" width={28} height={28} style={{
              filter: 'grayscale(1) sepia(1) hue-rotate(-50deg) saturate(4)',
          }} />}
            title="Cobalt Strike Module"
            status="upcoming"
            content="Generate malleable C2 profiles"
            buttonText="Access module"
            onAction={() => console.log("click")}
          />
        </Grid>*/}
      </Grid>

      <Toolbar disableGutters sx={{ gap: 0, mt: "2rem", mb: "1rem" }}>
        <Icon icon="solar:code-file-linear" width="32" height="32" color={theme.palette.error.main} style={{ marginRight: '1rem' }} />
        <Box display="flex" justifyContent="space-between" alignItems="center" width="100%">
          <Typography variant="h6" color="lightgray" sx={{ fontWeight: 800 }}>
            Generated Files
          </Typography>
          <Typography variant="body2" color="grey" sx={{ fontWeight: 600 }}>
            [{builds.length} FILE{builds.length === 1 ? '' : 'S'}]
          </Typography>
        </Box>
      </Toolbar>
      
      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}
      
      {loading ? (
        <Box display="flex" justifyContent="center" my={4}>
          <CircularProgress />
        </Box>
      ) : builds.length === 0 ? (
        <Box 
          display="inline-flex"
          justifyContent="center"
          alignItems="center"
          minHeight="100px"
          sx={{ 
            px: 5,
            py: 2,
            mx: 'auto',
            backgroundColor: alpha(theme.palette.error.main, 0.05),
            borderRadius: 2.5,
            display: 'flex',
            width: 'fit-content',
          }}
        >
          <Typography variant="body1" color="text.secondary">
            No builds found. Create your first build to get started!
          </Typography>
        </Box>
      ) : (
        <Grid container spacing={2}>
          {builds
            .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
            .map((build) => (
            <Grid size={{ xs: 12 }} key={build.id}>
              <FileListCard
                icon={<Icon icon="solar:code-file-linear" width="22" height="22" color={theme.palette.primary.main} />}
                file_data={{
                  id: build.id,
                  filename: build.filename,
                  created_at: new Date(build.created_at).toLocaleString(),
                  size: formatFileSize(build.size),
                }}
                onDelete={() => handleDeleteBuild(build.id)}
                onDownload={() => downloadBuild(build.id)}
                onViewDetails={() => navigate(`/file-details/${build.id}`)}
              />
            </Grid>
          ))}
        </Grid>
      )}
      {(message || error) && (
        <Snackbar
          open={openAlert} 
          autoHideDuration={3000}
          onClose={() => setOpenAlert(false)}
        >
          <Alert severity="success" sx={{ width: '100%' }}>
            {message || error}
          </Alert>
        </Snackbar>
      )}
    </HomeLayout>
  )
}
