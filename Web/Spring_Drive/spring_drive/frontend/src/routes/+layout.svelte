<script lang="ts">
	import favicon from '$lib/assets/icon.png';

	import Navbar from '../components/Navbar.svelte';

	let { children } = $props();
</script>

<svelte:head>
	<title>Drive</title>
	<link rel="icon" href={favicon} />
</svelte:head>

<Navbar />

{@render children?.()}

