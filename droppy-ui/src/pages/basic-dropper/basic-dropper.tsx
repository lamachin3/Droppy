import { useState, useEffect, useRef } from 'react';
import { useForm, FormProvider } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import { Button, Typography, useTheme, Toolbar, alpha, CircularProgress, Backdrop, Snackbar, Alert, Grid } from '@mui/material';
import { Icon } from '@iconify/react';
import { useNavigate } from 'react-router-dom';
import BasicDropperFeatures from './basic-features';
import BasicDropperInput from './basic-input';
import BasicDropperOutput from './basic-output';
import BasicDropperOptions from './basic-options';
import { buildSchemaFromConfig, type BasicDropperFormValues } from './form-validations';
import type { ObjectSchema } from 'yup';
import { getBasicDropperOptions, buildBasicDropper } from '@/services/api/dropperService';
import BasicDropperLayout from '@/layouts/basic-dropper';
import { BaseAutocomplete, PanelCard } from '@/components';
import { listTemplates } from '@/services/api/configTemplatesService';
import type { DropperOptions } from '@/services/api/dropperService';


export default function BasicDropper() {
	const theme = useTheme();
	const navigate = useNavigate();
	
	// State variables
	const [formConfig, setFormConfig] = useState<any | null>(null);
	const [templates, setTemplates] = useState<DropperOptions[] | null>([]);
	const [schema, setSchema] = useState<ObjectSchema<any> | null>(null);
	
	const [error, setError] = useState<Error | null>(null);
	const [message, setMessage] = useState<string | null>(null);
	const [openSnackbar, setOpenSnackbar] = useState(false);
	
	const [isLoading, setIsLoading] = useState(true);
	const [isBuilding, setIsBuilding] = useState(false);
	const [success, setSuccess] = useState<string | null>(null);
	const fileInputRef = useRef<HTMLInputElement>(null);
	
	
	useEffect(() => {
		const fetchDropperOptions = async () => {
			try {
				const data = await getBasicDropperOptions();
				setFormConfig(data);
				setSchema(buildSchemaFromConfig(data));

				const config_tempales = await listTemplates();
				setTemplates(config_tempales.results);
			} catch (err) {
				setError(err instanceof Error ? err : new Error('Failed to load options'));
			} finally {
				setIsLoading(false);
			}
		};
		
		fetchDropperOptions();
	}, []);

	const handleSetTemplate = (template: DropperOptions) => {
		if (template) {
			const local_injection_techniques = ["APC_INJECTION"];

			Object.entries(template.features).forEach(([key, value]) => {
				if (key === "injector" && value) {
					if (local_injection_techniques.includes(value as string)) {
						methods.setValue("local_injection", true);
					} else {
						methods.setValue("remote_injection", true);
					}
				} else {
					methods.setValue(key, Boolean(value));
				}
			});
			Object.entries(template.options).forEach(([key, value]) => {
				if (typeof value === "boolean") {
					methods.setValue(key, Boolean(value));
				} else {
					methods.setValue(key, String(value));
				}
			});

			setMessage(`Template "${template.name}" loaded successfully`);
			setOpenSnackbar(true);
		}
	};

	const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
		const file = event.target.files?.[0];
		if (!file) return;
		
		try {
			// read file content
			const reader = new FileReader();
			reader.onload = (e) => {
				const content = e.target?.result;
				if (typeof content === 'string') {
					const template = JSON.parse(content);
					handleSetTemplate(template);
				}
			};
			reader.readAsText(file);
		} catch (error) {
			console.error('Error reading template:', error);
			setError(error instanceof Error ? error : new Error('Failed to upload template'));
			setOpenSnackbar(true);
		} finally {
			if (fileInputRef.current) {
				fileInputRef.current.value = '';
			}
		}
	};

	const handleUploadClick = () => {
		fileInputRef.current?.click();
	};
	
	const methods = useForm({
		resolver: yupResolver(schema),
		defaultValues: {
			...(Array.isArray(formConfig?.features) ? Object.fromEntries(formConfig?.features.map(f => [f.name, ''])) : {}),
			uploadedShellcode: [],
			rawShellcode: '',
			githubPayload: '',
			executionArgs: '',
			outputFilename: 'dropper',
			outputExtension: formConfig?.output?.file_extension?.[0]?.value ?? '.exe',
			remote_process_name: '',
		}
	});
	
	
	const onSubmit = async (data: BasicDropperFormValues) => {
		try {
			setError(null);
			setIsBuilding(true);
			
			const formData = new FormData();
			
			// Add features
			formData.append('local_injection', String(data.local_injection || false));
			formData.append('remote_injection', String(data.remote_injection || false));
			formData.append('loader', String(data.loader || false));
			formData.append('obfuscation', String(data.obfuscation || false));
			formData.append('amsi_bypass', String(data.amsi_bypass || false));
			formData.append('etw_bypass', String(data.etw_bypass || false));
			formData.append('unhooking', String(data.unhooking || false));
			formData.append('syscalls', String(data.syscalls || false));
			
			// Add options
			formData.append('debug_mode', String(data.debug_mode || false));
			formData.append('hide_console', String(data.hide_console ?? true));
			formData.append('redirect_output', String(data.redirect_output || false));
			formData.append('remote_process_name', data.remote_process_name || '');
			
			// Add input
			formData.append("shellcode_text", data.rawShellcode || "");
			formData.append("github_url", data.githubPayload || "");
			formData.append('execution_args', data.execution_args || "");
			formData.append('remote_process_name', data.remote_process_name || "");

			const files: File[] = data.uploadedShellcode || [];
			files.forEach((file: File, idx: number) => {
				formData.append("shellcode", file, file.name);
			});
			
			// Add output
			formData.append('filename', data.filename || 'dropper');
			formData.append('file_extension', data.file_extension || '.exe');
			
			const response = await buildBasicDropper(formData);
			setSuccess('Dropper built successfully!');
			
			if (response.file_url) {
				navigate(response.file_url);
			}
		} catch (error: unknown) {
			const errorMessage = error instanceof Error ? error.message : 'Failed to build dropper';
			setError(new Error(errorMessage));
		} finally {
			setIsBuilding(false);
		}
	};

	if (isLoading || !schema || isBuilding) {
		return (
			<Backdrop
				sx={{ color: '#fff', zIndex: theme.zIndex.drawer + 1 }}
				open={isBuilding}
			>
				<CircularProgress />
			</Backdrop>
		);
	}
	
	return (
		<BasicDropperLayout>
			<Button 
				variant="text" 
				sx={{ 
					mb: 2, 
					display: 'flex', 
					alignItems: 'center', 
					gap: 1, 
					color: theme.palette.primary.contrastText, 
					'&:hover': { 
						color: theme.palette.primary.main, 
						backgroundColor: 'transparent' 
					} 
				}} 
				onClick={() => navigate('/')}
			>
				<Icon icon="ph:arrow-left" width="20" height="20" /> Back to Home
			</Button>
			
			<Toolbar disableGutters sx={{ gap: 2, mb: '1.5rem' }}>
				<Icon icon="solar:magic-stick-3-linear" width="36" height="36" style={{ marginRight: '1rem' }} />
				<div>
				<Typography variant="h5" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, fontSize: '1.8rem' }}>
					Basic Dropper Builder
				</Typography>
				<Typography variant="body1" color={alpha(theme.palette.primary.contrastText, 0.7)} sx={{ fontWeight: 500 }}>
					Payload generator with predefined evasion techniques
				</Typography>
				</div>
			</Toolbar>

			<PanelCard sx={{ my: 2, py: 1 }} >
				<Grid container sx={{ width: '100%' }}>
				<Grid size={{ xs: 0.5 }} sx={{ display: "flex", alignItems: "center", justifyContent: "flex-start" }}>
					<Icon icon="solar:code-file-linear" width="36" height="36" style={{ marginRight: '1rem' }} />
				</Grid>
				<Grid size={{ xs: 11, md: 5 }} sx={{ display: "flex", flexDirection: "column" }}>
					<Typography variant="h6" color={theme.palette.primary.contrastText}>
					Load Template
					</Typography>
					<Typography variant="body1" color={alpha(theme.palette.primary.contrastText, 0.7)}>
					Autofill with pre-configured dropper options
					</Typography>
				</Grid>
				<Grid size={{ xs: 12, md: 2.5 }} sx={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
					<>
						<input
							type="file"
							ref={fileInputRef}
							onChange={handleFileUpload}
							accept=".json"
							style={{ display: 'none' }}
						/>
						<Button
							component="label"
							role={undefined}
							variant="outlined"
							tabIndex={-1}
							onClick={handleUploadClick}
							startIcon={<Icon icon="solar:cloud-upload-bold" />}
							sx={{
								"&.Mui-disabled": {
									color: alpha(theme.palette.primary.contrastText, 0.2),
									borderColor: alpha(theme.palette.primary.contrastText, 0.2),
								}
							}}
						>
							Upload template
						</Button>
					</>
				</Grid>
				<Grid size={{ xs: 12, md: 4 }} sx={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}>
					<BaseAutocomplete
						name="config_template"
						options={templates || []}
						label="Select Template"
						getOptionLabel={(template: DropperOptions) => template.name}
						onChange={handleSetTemplate}
						sx={{ width: '90%' }}
					/>
				</Grid>
				</Grid>
			</PanelCard>
			
			<FormProvider {...methods}>
				<form onSubmit={methods.handleSubmit(onSubmit)}>
					<Grid container spacing={3}>
						<Grid size={{ xs: 12, md: 6 }}>
							<BasicDropperFeatures
								features={formConfig?.features}
							/>
							<BasicDropperOptions
								options={formConfig?.options}
							/>
						</Grid>
						<Grid size={{ xs: 12, md: 6 }}>
							<BasicDropperInput 
								github_executables={formConfig?.input.github || []}
							/>
							<BasicDropperOutput
								fileExtensions={formConfig?.output.file_extension || [{ value: '.exe', label: 'Windows Executable (.exe)' }]}
							/>
						</Grid>
					</Grid>
				</form>
			</FormProvider>
			{openSnackbar && (
				<Snackbar 
					open={openSnackbar} 
					autoHideDuration={6000}
					onClose={() => setOpenSnackbar(false)}
				>
					{error ? (
						<Alert severity="error" sx={{ width: '100%' }}>
							{error?.message}
						</Alert>
					) : (
						<Alert severity="success" sx={{ width: '100%' }}>
							{message}
						</Alert>
					)}
				</Snackbar>
			)}
		</BasicDropperLayout>
	);
}
