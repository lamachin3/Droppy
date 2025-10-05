import { useState, useEffect, useRef } from 'react';
import { useForm, FormProvider } from 'react-hook-form';
import { yupResolver } from '@hookform/resolvers/yup';
import type { ObjectSchema } from 'yup';
import { CircularProgress, Alert, Snackbar, Button, Typography, useTheme, alpha, Grid, Toolbar, Backdrop } from '@mui/material';
import { Icon } from '@iconify/react';
import { useNavigate } from 'react-router-dom';
import { AdvancedDropperLayout } from '@/layouts/advanced-dropper';
import AdvancedFeatures from './advanced-features';
import AdvancedInput from './advanced-input';
import AdvancedOptions from './advanced-options';
import AdvancedOutput from './advanced-output';
import type { CheckboxOption } from './types';
import { getAdvancedDropperOptions, type DropperOptions } from '@/services/api/dropperService';
import { buildSchemaFromConfig } from './form-validation';
import { buildDropper } from '@/services/api/dropperService';
import { listTemplates } from '@/services/api/configTemplatesService';
import { BaseAutocomplete, PanelCard } from '@/components';


export default function AdvancedDropper() {
	const theme = useTheme();
	const navigate = useNavigate();
	
	// State variable for the form options & validation schema
	const [formConfig, setFormConfig] = useState<DropperOptions | null>(null);
	const [templates, setTemplates] = useState<DropperOptions[] | null>([]);
	const [schema, setSchema] = useState<ObjectSchema<any> | null>(null);
	
	// State variable for the form errors
	const [error, setError] = useState<Error | null>(null);
	const [message, setMessage] = useState<string | null>(null);
	const [openSnackbar, setOpenSnackbar] = useState(false);
	
	// State variables for the component
	const [options, setOptions] = useState<CheckboxOption[]>([]);
	const [isLoading, setIsLoading] = useState(true);
	const [isBuilding, setIsBuilding] = useState(false);
	const fileInputRef = useRef<HTMLInputElement>(null);
	
	// Fetch dropper options on component mount
	useEffect(() => {
		const fetchDropperOptions = async () => {
			try {
				const data = await getAdvancedDropperOptions();
				setFormConfig(data);
				setSchema(buildSchemaFromConfig(data));
				
				const config_tempales = await listTemplates();
				setTemplates(config_tempales.results);
			} catch (err) {
				setError(err instanceof Error ? err : new Error('Failed to load options'));
				setOpenSnackbar(true);
			} finally {
				setIsLoading(false);
			}
		};
		
		fetchDropperOptions();
	}, []);
	
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
	
	const handleSetTemplate = (template: DropperOptions) => {
		if (template) {
			Object.entries(template.features).forEach(([key, value]) => {
				methods.setValue(key, value);
			});
			Object.entries(template.options).forEach(([key, value]) => {
				methods.setValue(key, value);
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
	
	const handleBuild = async (data: any) => {
		try {
			// normalize features (collapse [] -> "")
			const features_data = Object.fromEntries(
				(formConfig?.features || []).map((f: any) => {
					let value = data[f.name];
					if (Array.isArray(value) && value.length === 0) value = "";
					// if single-element arrays should be string:
					if (Array.isArray(value) && value.length === 1) value = value[0];
					return [f.name, value];
				})
			);
			
			// Create FormData
			const formData = new FormData();
			
			// Attach simple string fields
			Object.entries(features_data).forEach(([k, v]) => {
				// convert non-string values to JSON so backend can parse (optional)
				if (v === null || v === undefined) return;
				if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
					formData.append(k, String(v));
				} else {
					formData.append(k, JSON.stringify(v));
				}
			});
			
			formData.append("filename", data.outputFilename ?? "");
			formData.append("file_extension", data.outputExtension ?? "");
			formData.append("shellcode_text", data.rawShellcode ?? "");
			formData.append("github_url", data.githubPayload ?? "");
			formData.append("execution_args", data.executionArgs ?? "");
			formData.append("binary_signing", data.binarySigning ? JSON.stringify(data.binarySigning) : "");
			formData.append("debug_mode", String(!!data.debug_mode));
			formData.append("hide_console", String(!!data.hide_console));
			formData.append("redirect_output", String(!!data.redirect_output));
			formData.append("remote_process_name", data.remote_process_name ?? "");
			
			const files: File[] = data.uploadedShellcode || [];
			files.forEach((file: File, idx: number) => {
				formData.append("shellcode", file, file.name);
			});
			
			setIsBuilding(true);
			const response = await buildDropper(formData);
			
			navigate(response.file_url);
			setIsBuilding(false);
			
		} catch (error) {
			setError(error instanceof Error ? error : new Error('Failed to build dropper'));
			setIsBuilding(false);
		}
	};
	
	if (isLoading || !schema || isBuilding) {
		return (
			<Backdrop
				sx={{ color: theme.palette.primary.main, zIndex: (theme) => theme.zIndex.drawer + 1 }}
				open
			>
				<CircularProgress color="inherit" />
			</Backdrop>
		);
	}
	
	return (
		<AdvancedDropperLayout>
			<Button 
				variant="text" 
				sx={{ 
					mb: 2, 
					display: 'flex', 
					alignItems: 'center', 
					gap: 1, 
					color: theme.palette.primary.contrastText, 
					"&:hover": { 
						color: theme.palette.primary.main, 
						backgroundColor: "transparent" 
					} 
				}} 
				onClick={() => navigate('/')}
			>
				<Icon icon="ph:arrow-left" width="20" height="20" /> Back to Home
			</Button>
			
			<Toolbar disableGutters sx={{ gap: 2, mb: "1.5rem" }}>
				<Icon icon="solar:mask-happly-linear" width="36" height="36" style={{ marginRight: '1rem' }} />
				<div>
					<Typography variant="h5" color={theme.palette.primary.contrastText} sx={{ fontWeight: 800, fontSize: "1.8rem" }}>
						Advanced Stealth Builder
					</Typography>
					<Typography variant="body1" color={alpha(theme.palette.primary.contrastText, 0.7)} sx={{ fontWeight: 500 }}>
						Enhanced dropper with fine-grained control over implemented evasion techniques
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
					<Grid 
						size={{ xs: 12, md: 2.5 }} 
						sx={{ display: "flex", alignItems: "center", justifyContent: "flex-end" }}
					>
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
				<form onSubmit={methods.handleSubmit(handleBuild)}>
					<Grid container spacing={3}>
						<Grid size={{ xs: 12, md: 6 }}>
							<AdvancedFeatures
								modules={formConfig?.features || {}}
							/>
						</Grid>
						<Grid size={{ xs: 12, md: 6 }}>
							<AdvancedInput
								github_executables={formConfig?.input.github || []}
							/>
						
							<AdvancedOptions
								formOptions={formConfig?.options || []}
								options={options}
								injectors={formConfig?.features.find((f: any) => f.name === 'injector')?.options || []}
							/>
						
							<AdvancedOutput
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
		</AdvancedDropperLayout>
	);
}
