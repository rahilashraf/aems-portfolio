import { zodResolver } from "@hookform/resolvers/zod";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useForm } from "react-hook-form";
import { describe, expect, it, vi } from "vitest";
import { z } from "zod";

import { axeViolations } from "@/test/axe";

import { TextField } from "./text-field";

const schema = z.object({ name: z.string().min(2, "Enter at least 2 characters.") });

function Form({ onValid }: { onValid: (values: z.infer<typeof schema>) => void }) {
  const form = useForm({ resolver: zodResolver(schema), defaultValues: { name: "" } });
  return (
    <form onSubmit={form.handleSubmit(onValid)} noValidate>
      <TextField control={form.control} name="name" label="Name" description="Your display name." />
      <button type="submit">Save</button>
    </form>
  );
}

describe("TextField", () => {
  it("labels the input and links its description", async () => {
    const { container } = render(<Form onValid={vi.fn()} />);
    const input = screen.getByLabelText("Name");
    expect(input).not.toHaveAttribute("aria-invalid");
    expect(input).toHaveAccessibleDescription("Your display name.");
    expect(await axeViolations(container)).toEqual([]);
  });

  it("marks the field invalid and announces the error, then clears it", async () => {
    const onValid = vi.fn();
    const user = userEvent.setup();
    const { container } = render(<Form onValid={onValid} />);
    await user.click(screen.getByRole("button", { name: "Save" }));

    const input = screen.getByLabelText("Name");
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription(
      /Your display name\.\s*Enter at least 2 characters\./,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Enter at least 2 characters.");
    expect(onValid).not.toHaveBeenCalled();
    expect(await axeViolations(container)).toEqual([]);

    await user.type(input, "Ada");
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(onValid).toHaveBeenCalledWith({ name: "Ada" }, expect.anything());
    expect(input).not.toHaveAttribute("aria-invalid");
  });

  it("works without a description", () => {
    function Bare() {
      const form = useForm({ defaultValues: { code: "" } });
      return <TextField control={form.control} name="code" label="Code" />;
    }
    render(<Bare />);
    expect(screen.getByLabelText("Code")).not.toHaveAttribute("aria-describedby");
  });
});
