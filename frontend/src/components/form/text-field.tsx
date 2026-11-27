"use client";

import { type ComponentProps, useId } from "react";
import { Controller, type Control, type FieldPath, type FieldValues } from "react-hook-form";

import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

type InputProps = Omit<
  ComponentProps<typeof Input>,
  | "name"
  | "value"
  | "defaultValue"
  | "onChange"
  | "onBlur"
  | "id"
  | "aria-invalid"
  | "aria-describedby"
>;

interface TextFieldProps<TValues extends FieldValues> extends InputProps {
  control: Control<TValues>;
  name: FieldPath<TValues>;
  label: string;
  description?: string;
}

/**
 * Accessible text input bound to React Hook Form: the label is associated with the input, and the
 * description and validation error are linked through `aria-describedby`; an invalid field sets
 * `aria-invalid`. Validation rules come from the form's (Zod) resolver.
 */
export function TextField<TValues extends FieldValues>({
  control,
  name,
  label,
  description,
  ...inputProps
}: TextFieldProps<TValues>) {
  const id = useId();
  const descriptionId = `${id}-description`;
  const errorId = `${id}-error`;

  return (
    <Controller
      control={control}
      name={name}
      render={({ field, fieldState }) => {
        const invalid = fieldState.invalid;
        const describedBy =
          [description ? descriptionId : null, invalid ? errorId : null]
            .filter(Boolean)
            .join(" ") || undefined;
        return (
          <Field data-invalid={invalid || undefined}>
            <FieldLabel htmlFor={id}>{label}</FieldLabel>
            <Input
              {...inputProps}
              {...field}
              id={id}
              value={(field.value as string | undefined) ?? ""}
              aria-invalid={invalid || undefined}
              aria-describedby={describedBy}
            />
            {description ? (
              <FieldDescription id={descriptionId}>{description}</FieldDescription>
            ) : null}
            {invalid ? <FieldError id={errorId} errors={[fieldState.error]} /> : null}
          </Field>
        );
      }}
    />
  );
}
