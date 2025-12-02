import { writable } from 'svelte/store';

export type ExplanationMode = 'founder' | 'developer';

function createPreferencesStore() {
	const stored = typeof localStorage !== 'undefined'
		? localStorage.getItem('vibeship-mode') as ExplanationMode
		: null;

	const { subscribe, set, update } = writable<ExplanationMode>(stored || 'founder');

	return {
		subscribe,
		setMode: (mode: ExplanationMode) => {
			if (typeof localStorage !== 'undefined') {
				localStorage.setItem('vibeship-mode', mode);
			}
			set(mode);
		},
		toggle: () => {
			update(current => {
				const newMode = current === 'founder' ? 'developer' : 'founder';
				if (typeof localStorage !== 'undefined') {
					localStorage.setItem('vibeship-mode', newMode);
				}
				return newMode;
			});
		}
	};
}

export const explanationMode = createPreferencesStore();
