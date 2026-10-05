import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { VerdictBadge } from './VerdictBadge';

describe('VerdictBadge', () => {
  it('renders NOT_DETERMINED as a first-class verdict', () => {
    render(<VerdictBadge verdict="NOT_DETERMINED" />);
    expect(screen.getByText('NOT DETERMINED')).toHaveClass('verdict-not_determined');
  });
});
