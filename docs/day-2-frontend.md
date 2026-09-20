# Day 2 Frontend Architecture

## Stack

- React + TypeScript + Vite
- CSS variables for the design system
- React Router for route-based navigation and SPA flow
- Static mock data for interface validation and product storytelling

## Folder Structure

```text
frontend/
├── src/
│   ├── data/
│   ├── App.tsx
│   ├── App.css
│   ├── index.css
│   ├── main.tsx
│   └── types.ts
├── index.html
├── package.json
├── vite.config.ts
├── tsconfig.json
└── .env.example
```

## Routes

- `/` landing page
- `/login`
- `/register`
- `/onboarding`
- `/dashboard`
- `/websites`
- `/websites/add`
- `/scans`
- `/findings`
- `/findings/:id`
- `/reports`
- `/monitoring`
- `/ai-assistant`
- `/settings`
- `*` fallback 404 page

## Components

- AppShell
- Sidebar
- Topbar
- PageHeader
- Card
- StatCard
- SeverityBadge
- StatusBadge
- FindingCard
- WebsiteCard
- EmptyState
- ErrorState
- SkeletonCard
- SkeletonTable
- SkeletonChart
- SkeletonPage

## Mock Data

Mock data includes demo users, businesses, websites, scans, findings, reports, monitoring targets, notifications, and dashboard stats. It is intentionally stored separately from page components to support easier updates and future API replacement.

## Accessibility

- Semantic landmarks and labels are used throughout the interface.
- Focus states are visible for keyboard users.
- Severity uses both text and a visual indicator.
- Navigation remains operable with a keyboard.
- Theme and reduced motion decisions support better usability for diverse users.
