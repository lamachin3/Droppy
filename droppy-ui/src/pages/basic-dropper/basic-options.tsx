import { Icon } from "@iconify/react/dist/iconify.js";
import { Box, FormControlLabel, FormGroup, useTheme, FormControl, InputLabel, Select, MenuItem, Tooltip } from "@mui/material";
import { Controller, useFormContext } from 'react-hook-form';
import { FormCheckbox, FormTextField, PanelCard } from "@/components";


export default function BasicDropperOptions({ options }: { options: any }) {
  const theme = useTheme();
  const { control, watch, setValue } = useFormContext();

  const remote_injection = watch("remote_injection");
  const binarySigning = watch('binary_signing');
  const signingMethod = watch('signing_method', 'none');

  return (
    <PanelCard
        icon={<Icon icon="solar:settings-linear" width="28" height="28" color={theme.palette.primary.contrastText} />}
        title="Global Options"
        sx={{ mt: 2 }}
    >
      	<Box>
			<FormGroup>
				{options?.map((option: any) => !option.conditional ? (
					<Controller
						key={option.value}
						name={option.value}
						control={control}
						defaultValue={false}
						render={({ field }) => (
							<Tooltip key={option.value} title={option.description} enterDelay={500}>
								<FormControlLabel
									control={
										<FormCheckbox
											{...field}
											checked={!!field.value}
										/>
									}
									label={option.label}
								/>
						</Tooltip>
						)}
					/>
				) : null)}

				{remote_injection && (
					<Controller
						key="remote_process_name"
						name="remote_process_name"
						control={control}
						defaultValue=""
						render={({ field }) => (
							<FormTextField
								{...field}
								label="Remote Process Name"
								sx={{ mt: 2 }}
								placeholder="runtimebroker.exe"
							/>
						)}
					/>
				)}
          
				{binarySigning && (
					<Box sx={{ mt: 2 }}>
					<FormControl fullWidth sx={{ mb: 2 }}>
						<InputLabel id="signing-method-label">Signing Method</InputLabel>
						<Select
						labelId="signing-method-label"
						id="signing_method"
						value={signingMethod}
						label="Signing Method"
						onChange={(e) => setValue('signing_method', e.target.value, { shouldValidate: true })}
						>
						<MenuItem value="none">None</MenuItem>
						<MenuItem value="self_signed">Self-Signed Certificate</MenuItem>
						<MenuItem value="import">Import Certificate</MenuItem>
						</Select>
					</FormControl>

					{signingMethod === 'import' && (
						<Box>
						<FormTextField
							name="certificate_path"
							control={control}
							label="Certificate Path"
							placeholder="Path to certificate file"
						/>
						<FormTextField
							name="private_key_path"
							control={control}
							label="Private Key Path"
							placeholder="Path to private key file"
						/>
						<FormTextField
							name="certificate_password"
							control={control}
							label="Password (if any)"
							type="password"
							placeholder="Enter certificate password"
						/>
						</Box>
					)}

					{signingMethod === 'self_signed' && (
						<Box>
						<FormTextField
							name="common_name"
							control={control}
							label="Common Name (CN)"
							placeholder="e.g., My Organization"
						/>
						<FormTextField
							name="organization"
							control={control}
							label="Organization (O)"
							placeholder="e.g., My Company Inc."
						/>
						<FormTextField
							name="organizational_unit"
							control={control}
							label="Organizational Unit (OU)"
							placeholder="e.g., IT Department"
						/>
						<FormTextField
							name="country"
							control={control}
							label="Country (C)"
							placeholder="e.g., US"
							inputProps={{ maxLength: 2 }}
						/>
						<FormTextField
							name="valid_days"
							control={control}
							label="Valid For (Days)"
							type="number"
							defaultValue={365}
							inputProps={{ min: 1 }}
						/>
						</Box>
					)}
					</Box>
				)}
			</FormGroup>
      </Box>
    </PanelCard>
  );
}
